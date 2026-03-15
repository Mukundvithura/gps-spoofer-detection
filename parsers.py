#!/usr/bin/env python3
"""
=============================================================================
Module : parsers.py
Purpose: Parse all acquired Android forensic artefacts into structured
         Python data suitable for the detection and timeline engines.
=============================================================================

Parsed artefact types:
  1. settings_secure.xml    → mock_location_enabled, developer_options state
  2. package_list.txt       → installed app inventory, spoofing app detection
  3. herrevad.db            → GPS location records (latitude, longitude, time)
  4. netconn.db             → Cell tower records (MCC, MNC, LAC, CID, time)
  5. location_cache.db      → Fused Location Provider cache
  6. da_destination_history.db → Google Maps navigation destinations
  7. logcat_dump.txt        → Mock location provider log entries
  8. dumpsys_location.txt   → Current location service state
"""

import os
import sqlite3
import xml.etree.ElementTree as ET
import datetime
import re


# ─────────────────────────────────────────────────────────────────────────────
# KNOWN GPS SPOOFING APP PACKAGE NAMES
# This list covers the most common consumer-grade spoofing applications
# available on Google Play Store and via sideload.
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_SPOOFING_PACKAGES = {
    "com.lexa.fakegps"                        : "Fake GPS Location by Lexa",
    "com.theappninjas.gpsjoy"                 : "GPS JoyStick by The App Ninjas",
    "com.incorporateapps.fakegps.fre"         : "Fake GPS Run! (Free)",
    "com.blogspot.newapphorizons.fakegpslocations": "Fake GPS Location Changer Free",
    "com.rosteam.gpsemulator"                 : "Fake GPS Location — GPS JoyStick",
    "com.fly.mock.location"                   : "Fake GPS — Mock Location",
    "com.fakegps.mock"                        : "Fake GPS Mock",
    "ru.gavrikov.mocklocations"               : "Mock Locations (fake GPS path)",
    "com.ssrlab.fakeLocation"                 : "Fake Location — GPS Spoofer",
    "com.evezzon.fakegps"                     : "Fake GPS Location Spoofer Pro",
}


# ─────────────────────────────────────────────────────────────────────────────
# ARTEFACT PARSER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactParser:
    """
    Reads all acquired forensic artefacts and returns a unified parsed_data
    dictionary consumed by the detection and timeline engines.

    Args:
        artefact_root : Root directory containing acquired files
                        (mirrors Android directory structure)
        verbose       : Print debug info when True
    """

    def __init__(self, artefact_root: str, verbose: bool = False):
        self.root    = artefact_root
        self.verbose = verbose

    # ── Resolve a device path to a local path ─────────────────────────────────

    def _local(self, *path_parts) -> str:
        """
        Build a local filesystem path by joining artefact_root with
        the relative version of an Android device path.

        Example:
            _local("data/system/users/0/settings_secure.xml")
            → "/path/to/acquisition/data/system/users/0/settings_secure.xml"
        """
        return os.path.join(self.root, *path_parts)

    def _dbg(self, msg: str):
        """Print debug message if verbose mode is on."""
        if self.verbose:
            print(f"    [DBG] {msg}")

    # ─────────────────────────────────────────────────────────────────────────
    # MASTER PARSE FUNCTION
    # ─────────────────────────────────────────────────────────────────────────

    def parse_all(self) -> dict:
        """
        Run all parsers and return a unified dictionary:

        {
          'mock_location_enabled'  : bool,
          'developer_options_ts'   : int (epoch ms) or None,
          'mock_location_package'  : str or None,
          'mock_location_set_ts'   : int (epoch ms) or None,
          'spoofing_apps'          : [ {'package': ..., 'name': ..., 'install_ts': ...} ],
          'gps_records'            : [ {'lat', 'lng', 'accuracy', 'provider', 'ts_ms'} ],
          'cell_records'           : [ {'mcc', 'mnc', 'lac', 'cid', 'signal', 'ts_ms'} ],
          'fused_records'          : [ {'lat', 'lng', 'accuracy', 'provider', 'ts_ms'} ],
          'map_destinations'       : [ {'lat', 'lng', 'name', 'ts_ms'} ],
          'app_usage'              : [ {'package', 'event', 'ts_ms'} ],
          'logcat_mock_events'     : [ {'line', 'ts_str'} ],
          'all_packages'           : [ str ],
        }
        """
        parsed = {}

        # Settings: mock_location and developer options
        parsed.update(self._parse_settings_secure())

        # Package list: installed apps + spoofing app detection
        parsed.update(self._parse_package_list())

        # GPS records from GMS herrevad.db
        parsed['gps_records'] = self._parse_location_db(
            path    = self._local("data/data/com.google.android.gms/databases/herrevad.db"),
            table   = "locations",
            lat_col = "latitude",
            lng_col = "longitude",
            ts_col  = "timestamp",
            extra_cols=["accuracy", "provider"]
        )

        # Cell tower records from netconn.db
        parsed['cell_records'] = self._parse_cell_db()

        # Fused location cache
        parsed['fused_records'] = self._parse_location_db(
            path    = self._local("data/data/com.google.android.gms/databases/location_cache.db"),
            table   = "fused_locations",
            lat_col = "latitude",
            lng_col = "longitude",
            ts_col  = "timestamp",
            extra_cols=["accuracy", "provider"]
        )

        # Google Maps destination history
        parsed['map_destinations'] = self._parse_map_destinations()

        # Logcat mock location events
        parsed['logcat_mock_events'] = self._parse_logcat()

        # App usage (package list install times as a proxy)
        parsed['app_usage'] = self._parse_app_usage(parsed.get('spoofing_apps', []))

        return parsed

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: settings_secure.xml
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_settings_secure(self) -> dict:
        """
        Parse settings_secure.xml and settings_global.xml to extract:
          - Whether Developer Options are/were enabled
          - Whether a mock location app was designated
          - Timestamps of those settings changes
        """
        result = {
            'mock_location_enabled'  : False,
            'developer_options_ts'   : None,
            'mock_location_package'  : None,
            'mock_location_set_ts'   : None,
        }

        for xml_filename in ["settings_secure.xml", "settings_global.xml"]:
            xml_path = self._local("data/system/users/0", xml_filename)

            if not os.path.isfile(xml_path):
                self._dbg(f"{xml_filename} not found at {xml_path}")
                continue

            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()

                for setting in root.findall("setting"):
                    name     = setting.get("name", "")
                    value    = setting.get("value", "")
                    modified = setting.get("modified")

                    # Developer Options enablement
                    if name == "development_settings_enabled" and value == "1":
                        result['mock_location_enabled'] = True
                        if modified:
                            result['developer_options_ts'] = int(modified)
                        self._dbg(f"Developer Options enabled, modified={modified}")

                    # Mock location app designation (Android 6+)
                    elif name == "mock_location" and value:
                        result['mock_location_package'] = value
                        result['mock_location_enabled'] = True
                        if modified:
                            result['mock_location_set_ts'] = int(modified)
                        self._dbg(f"Mock location package: {value}, modified={modified}")

            except ET.ParseError as e:
                self._dbg(f"XML parse error in {xml_filename}: {e}")

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: package_list.txt
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_package_list(self) -> dict:
        """
        Parse the ADB package list dump to:
          - Build a complete list of all installed packages
          - Identify any known GPS spoofing applications
          - Extract install timestamps where available
        """
        result = {
            'all_packages' : [],
            'spoofing_apps': [],
        }

        pkg_path = os.path.join(self.root, "package_list.txt")
        if not os.path.isfile(pkg_path):
            self._dbg("package_list.txt not found")
            return result

        with open(pkg_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extract package name from lines like:
            # package:/data/app/com.lexa.fakegps-1/base.apk=com.lexa.fakegps
            pkg_match = re.search(r'=([a-zA-Z][a-zA-Z0-9._]+)', line)
            if not pkg_match:
                continue

            package_name = pkg_match.group(1)
            result['all_packages'].append(package_name)

            # Check against known spoofing app list
            if package_name in KNOWN_SPOOFING_PACKAGES:
                # Attempt to extract install timestamp
                ts_match = re.search(r'firstInstallTime=(\d+)', line)
                install_ts = int(ts_match.group(1)) * 1000 if ts_match else None

                entry = {
                    'package'    : package_name,
                    'name'       : KNOWN_SPOOFING_PACKAGES[package_name],
                    'install_ts' : install_ts,
                }
                result['spoofing_apps'].append(entry)
                self._dbg(f"Spoofing app detected: {package_name}")

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Generic SQLite location database
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_location_db(
        self,
        path: str,
        table: str,
        lat_col: str,
        lng_col: str,
        ts_col: str,
        extra_cols: list = None
    ) -> list:
        """
        Generic parser for SQLite databases containing location records.
        Returns a list of dicts with keys: lat, lng, ts_ms, plus extras.

        Timestamps are expected in Unix epoch milliseconds.
        """
        records = []

        if not os.path.isfile(path):
            self._dbg(f"DB not found: {path}")
            return records

        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            # Build SELECT with any extra columns requested
            cols = [lat_col, lng_col, ts_col]
            if extra_cols:
                cols += extra_cols
            query = f"SELECT {', '.join(cols)} FROM {table} ORDER BY {ts_col} ASC"

            cur.execute(query)
            rows = cur.fetchall()
            conn.close()

            for row in rows:
                record = {
                    'lat'   : row[lat_col],
                    'lng'   : row[lng_col],
                    'ts_ms' : row[ts_col],
                }
                if extra_cols:
                    for col in extra_cols:
                        record[col] = row[col]
                records.append(record)

            self._dbg(f"Parsed {len(records)} records from {os.path.basename(path)}/{table}")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading {path}: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: netconn.db — Cell Tower Records
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_cell_db(self) -> list:
        """
        Parse netconn.db for cell tower scan records.
        Cell towers are geographically bound — cannot be spoofed by app-level mock location.
        """
        records = []
        db_path = self._local("data/data/com.google.android.gms/databases/netconn.db")

        if not os.path.isfile(db_path):
            self._dbg("netconn.db not found")
            return records

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            cur.execute("""
                SELECT mcc, mnc, lac, cid, signal, timestamp
                FROM   cell_scan_results
                ORDER  BY timestamp ASC
            """)

            for row in cur.fetchall():
                records.append({
                    'mcc'    : row['mcc'],
                    'mnc'    : row['mnc'],
                    'lac'    : row['lac'],
                    'cid'    : row['cid'],
                    'signal' : row['signal'],
                    'ts_ms'  : row['timestamp'],
                })

            conn.close()
            self._dbg(f"Parsed {len(records)} cell tower records")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading netconn.db: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: da_destination_history.db — Google Maps Destinations
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_map_destinations(self) -> list:
        """
        Parse Google Maps navigation destination history.
        A destination in a distant city is significant if the device GPS
        simultaneously claims to be in that city.
        """
        records = []
        db_path = self._local(
            "data/data/com.google.android.apps.maps/databases/da_destination_history.db"
        )

        if not os.path.isfile(db_path):
            self._dbg("da_destination_history.db not found")
            return records

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            cur.execute("""
                SELECT dest_lat, dest_lng, dest_name, timestamp
                FROM   destination_history
                ORDER  BY timestamp ASC
            """)

            for row in cur.fetchall():
                records.append({
                    'lat'   : row['dest_lat'],
                    'lng'   : row['dest_lng'],
                    'name'  : row['dest_name'],
                    'ts_ms' : row['timestamp'],
                })

            conn.close()
            self._dbg(f"Parsed {len(records)} map destination records")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading destination history: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: logcat_dump.txt — Mock Location Log Events
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_logcat(self) -> list:
        """
        Scan logcat dump for lines containing mock location provider events.
        Key strings: 'MockLocationProvider', 'setTestProviderLocation',
                     'Mock provider enabled', 'Mock provider disabled'.
        """
        events  = []
        log_path = os.path.join(self.root, "logcat_dump.txt")

        if not os.path.isfile(log_path):
            self._dbg("logcat_dump.txt not found")
            return events

        mock_keywords = [
            "MockLocationProvider",
            "setTestProviderLocation",
            "Mock provider enabled",
            "Mock provider disabled",
            "mockLocation",
            "fakegps",
        ]

        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_lower = line.lower()
                if any(kw.lower() in line_lower for kw in mock_keywords):
                    # Extract timestamp prefix from logcat format MM-DD HH:MM:SS.mmm
                    ts_match = re.match(r'^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
                    ts_str   = ts_match.group(1) if ts_match else "unknown"
                    events.append({
                        'line'   : line.strip(),
                        'ts_str' : ts_str,
                    })
                    self._dbg(f"Logcat mock event: {ts_str}")

        return events

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: App Usage (derived from install timestamps)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_app_usage(self, spoofing_apps: list) -> list:
        """
        Build an app usage event list from:
          - Spoofing app install timestamps (from package_list)
          - Mock location setting timestamps (from settings_secure.xml)
          - Logcat events

        In a real investigation, /data/system/usagestats/ would provide
        richer usage data. This implementation uses available proxies.
        """
        usage_events = []

        for app in spoofing_apps:
            if app.get('install_ts'):
                usage_events.append({
                    'package'  : app['package'],
                    'event'    : 'INSTALL',
                    'ts_ms'    : app['install_ts'],
                })

        return usage_events


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: Convert Unix epoch milliseconds to UTC datetime string
# ─────────────────────────────────────────────────────────────────────────────

def epoch_ms_to_utc(ts_ms: int) -> str:
    """Convert Unix timestamp in milliseconds to a human-readable UTC string."""
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return f"INVALID_TS({ts_ms})"
