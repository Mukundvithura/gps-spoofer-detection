#!/usr/bin/env python3
"""
=============================================================================
Module : adb_acquire.py
Purpose: ADB-based forensic acquisition of Android artefacts.
         Also provides a demo artefact generator for offline testing.
=============================================================================

Responsibilities:
  - Connect to an ADB device and verify its state
  - Pull forensic artefacts from known Android paths
  - Record SHA-256 hash of every pulled file (chain of custody)
  - Generate synthetic demo artefacts that mirror real Android structures
"""

import os
import subprocess
import hashlib
import datetime
import sqlite3
import xml.etree.ElementTree as ET


# ─────────────────────────────────────────────────────────────────────────────
# KNOWN FORENSIC ARTEFACT PATHS ON ANDROID
# ─────────────────────────────────────────────────────────────────────────────

ARTEFACT_TARGETS = [
    # Developer / mock location settings
    "/data/system/users/0/settings_secure.xml",
    "/data/system/users/0/settings_global.xml",

    # Google Location Services databases
    "/data/data/com.google.android.gms/databases/herrevad.db",
    "/data/data/com.google.android.gms/databases/location_cache.db",
    "/data/data/com.google.android.gms/databases/netconn.db",

    # Google Maps history databases
    "/data/data/com.google.android.apps.maps/databases/da_destination_history.db",

    # Misc location data
    "/data/misc/location/",

    # Android package manager (installed app records)
    "/data/system/packages.xml",

    # App usage statistics
    "/data/system/usagestats/0/",
]


# ─────────────────────────────────────────────────────────────────────────────
# ADB CLIENT CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ADBClient:
    """
    Manages ADB communication for forensic artefact acquisition.

    Attributes:
        serial     : ADB device serial (None = first connected device)
        output_dir : Local directory to store pulled artefacts
        verbose    : Print debug output when True
        hash_log   : Dictionary mapping filename → SHA-256 hash
    """

    def __init__(self, serial: str, output_dir: str, verbose: bool = False):
        self.serial     = serial
        self.output_dir = output_dir
        self.verbose    = verbose
        self.hash_log   = {}
        os.makedirs(output_dir, exist_ok=True)

    # ── Internal: run ADB command ─────────────────────────────────────────────

    def _adb(self, *args) -> subprocess.CompletedProcess:
        """
        Run an ADB command and return the CompletedProcess result.
        Prepends '-s <serial>' if a serial number was specified.
        """
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)

        if self.verbose:
            print(f"    [ADB] {' '.join(cmd)}")

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

    # ── Check ADB device connection ───────────────────────────────────────────

    def check_connection(self) -> bool:
        """
        Verify that exactly one (or a specified) device is connected and
        accessible. Returns True if device is ready.
        """
        result = self._adb("devices")
        lines  = result.stdout.strip().splitlines()

        # Lines after header "List of devices attached"
        devices = [l for l in lines[1:] if l.strip() and "device" in l]

        if not devices:
            print("  [ERROR] No ADB device found. Connect device and enable USB Debugging.")
            return False

        # Extract serial from first device line for display
        connected_serial = devices[0].split()[0]
        print(f"  [OK]   Device detected: {connected_serial}")
        return True

    # ── Pull a single file or directory ──────────────────────────────────────

    def pull_path(self, device_path: str) -> bool:
        """
        Pull a single file or directory from the device to output_dir.
        Computes SHA-256 of pulled file and records it for chain of custody.
        Returns True on success.
        """
        # Build local destination path (mirror device path under output_dir)
        # e.g. /data/data/com.google.android.gms/databases/herrevad.db
        #    → output_dir/data/data/com.google.android.gms/databases/herrevad.db
        rel_path  = device_path.lstrip("/")
        local_dst = os.path.join(self.output_dir, rel_path)
        os.makedirs(os.path.dirname(local_dst), exist_ok=True)

        result = self._adb("pull", device_path, local_dst)

        if result.returncode != 0:
            # Non-fatal: path may not exist on this specific device build
            if self.verbose:
                print(f"  [WARN] Could not pull {device_path}: {result.stderr.strip()}")
            return False

        # Hash the pulled file(s) for chain of custody log
        if os.path.isfile(local_dst):
            sha256 = self._sha256(local_dst)
            self.hash_log[local_dst] = sha256
            print(f"  [PULL] {device_path}  →  SHA256: {sha256[:16]}...")
        else:
            print(f"  [PULL] {device_path}  (directory)")

        return True

    # ── Pull all target artefacts ─────────────────────────────────────────────

    def acquire_all(self) -> bool:
        """
        Orchestrate full artefact acquisition:
          1. Verify device connection
          2. Pull all known forensic paths
          3. Dump logcat buffer
          4. Dump device info (dumpsys location, package list)
          5. Write chain-of-custody hash log

        Returns True if at least one artefact was acquired.
        """
        if not self.check_connection():
            return False

        print(f"  [INFO] Acquiring {len(ARTEFACT_TARGETS)} target paths...")
        success_count = 0

        for target in ARTEFACT_TARGETS:
            if self.pull_path(target):
                success_count += 1

        # ── Supplementary dumps (non-file ADB commands) ────────────────────
        self._dump_logcat()
        self._dump_location_service()
        self._dump_package_list()

        # ── Write hash log ────────────────────────────────────────────────
        self._write_hash_log()

        if success_count == 0:
            print("  [ERROR] No artefacts could be pulled. Check device permissions.")
            return False

        print(f"  [OK]   Acquisition complete. {success_count} paths pulled.")
        return True

    # ── Supplementary dump: logcat ────────────────────────────────────────────

    def _dump_logcat(self):
        """Dump current logcat buffer to a text file."""
        result = self._adb("logcat", "-d", "-b", "all")
        if result.returncode == 0:
            path = os.path.join(self.output_dir, "logcat_dump.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(result.stdout)
            sha256 = self._sha256(path)
            self.hash_log[path] = sha256
            print(f"  [PULL] logcat buffer  →  SHA256: {sha256[:16]}...")

    # ── Supplementary dump: location service state ────────────────────────────

    def _dump_location_service(self):
        """Dump 'dumpsys location' output to a text file."""
        result = self._adb("shell", "dumpsys", "location")
        if result.returncode == 0:
            path = os.path.join(self.output_dir, "dumpsys_location.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(result.stdout)
            sha256 = self._sha256(path)
            self.hash_log[path] = sha256
            print(f"  [PULL] dumpsys location  →  SHA256: {sha256[:16]}...")

    # ── Supplementary dump: installed packages ────────────────────────────────

    def _dump_package_list(self):
        """Dump full package list to a text file."""
        result = self._adb("shell", "pm", "list", "packages", "-f", "-i")
        if result.returncode == 0:
            path = os.path.join(self.output_dir, "package_list.txt")
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(result.stdout)
            sha256 = self._sha256(path)
            self.hash_log[path] = sha256
            print(f"  [PULL] package list  →  SHA256: {sha256[:16]}...")

    # ── SHA-256 hash computation ───────────────────────────────────────────────

    @staticmethod
    def _sha256(filepath: str) -> str:
        """Compute SHA-256 hash of a local file."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── Write chain-of-custody hash log ──────────────────────────────────────

    def _write_hash_log(self):
        """Write all SHA-256 hashes to a hash manifest file."""
        log_path = os.path.join(self.output_dir, "CHAIN_OF_CUSTODY_HASHES.txt")
        with open(log_path, "w") as f:
            f.write("GPS SPOOFING FORENSIC TOOL — CHAIN OF CUSTODY HASH LOG\n")
            f.write(f"Generated: {datetime.datetime.utcnow().isoformat()} UTC\n")
            f.write("=" * 70 + "\n")
            for filepath, sha256 in self.hash_log.items():
                rel = os.path.relpath(filepath, self.output_dir)
                f.write(f"{sha256}  {rel}\n")
        print(f"  [OK]   Hash manifest written: {log_path}")

    # ─────────────────────────────────────────────────────────────────────────
    # DEMO ARTEFACT GENERATOR
    # ─────────────────────────────────────────────────────────────────────────

    def generate_demo_artefacts(self):
        """
        Generate a complete set of synthetic forensic artefacts that
        mirror the real Android directory structure and database schemas.

        This creates a realistic spoofing scenario:
          - Device physically in Chennai (cell towers, WiFi confirm this)
          - GPS records show sudden jump to Bengaluru (spoofed)
          - Fake GPS app installed / uninstalled within 30-minute window
          - Mock location setting was active during that window

        The synthetic data can be processed by all downstream modules
        exactly as real acquired data would be.
        """
        root = self.output_dir

        # ── settings_secure.xml ───────────────────────────────────────────
        settings_dir = os.path.join(root, "data/system/users/0")
        os.makedirs(settings_dir, exist_ok=True)

        # Timestamps representing the spoofing event window
        # Base: 2024-03-15 09:00:00 UTC
        base_ts = int(datetime.datetime(2024, 3, 15, 9, 0, 0).timestamp())

        secure_xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<settings version="196">
  <setting
    id="1"
    name="development_settings_enabled"
    value="1"
    package="android"
    defaultValue="0"
    modified="{(base_ts + 1320) * 1000}"
    _count="3" />
  <setting
    id="2"
    name="mock_location"
    value="com.lexa.fakegps"
    package="com.lexa.fakegps"
    defaultValue=""
    modified="{(base_ts + 1740) * 1000}"
    _count="2" />
  <setting
    id="3"
    name="adb_enabled"
    value="1"
    package="android"
    defaultValue="0"
    modified="{(base_ts + 0) * 1000}"
    _count="1" />
</settings>"""

        with open(os.path.join(settings_dir, "settings_secure.xml"), "w") as f:
            f.write(secure_xml_content)

        global_xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<settings version="196">
  <setting
    id="10"
    name="development_settings_enabled"
    value="1"
    package="android"
    defaultValue="0"
    modified="{(base_ts + 1320) * 1000}"
    _count="5" />
</settings>"""

        with open(os.path.join(settings_dir, "settings_global.xml"), "w") as f:
            f.write(global_xml_content)

        # ── package_list.txt ──────────────────────────────────────────────
        # Includes a known spoofing app entry
        package_list = (
            "package:/data/app/com.lexa.fakegps-1/base.apk=com.lexa.fakegps  "
            f"installer=com.android.vending  firstInstallTime={base_ts + 1560}  "
            f"lastUpdateTime={base_ts + 1560}\n"
            "package:/data/app/com.google.android.gms-2/base.apk=com.google.android.gms  "
            "installer=com.android.vending\n"
            "package:/data/app/com.google.android.apps.maps-5/base.apk=com.google.android.apps.maps  "
            "installer=com.android.vending\n"
            "package:/data/app/com.whatsapp-3/base.apk=com.whatsapp  "
            "installer=com.android.vending\n"
        )
        with open(os.path.join(root, "package_list.txt"), "w") as f:
            f.write(package_list)

        # ── herrevad.db (GMS Network Location History) ────────────────────
        gms_db_dir = os.path.join(root, "data/data/com.google.android.gms/databases")
        os.makedirs(gms_db_dir, exist_ok=True)

        herrevad_path = os.path.join(gms_db_dir, "herrevad.db")
        conn = sqlite3.connect(herrevad_path)
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                _id         INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude    REAL    NOT NULL,
                longitude   REAL    NOT NULL,
                accuracy    REAL,
                altitude    REAL,
                speed       REAL,
                provider    TEXT,
                timestamp   INTEGER NOT NULL
            )
        """)

        # Genuine Chennai records (before spoofing)
        # Chennai: 13.0827°N, 80.2707°E
        genuine_records = [
            (13.0820, 80.2700, 15.0, 6.0,   0.0,   "gps",    (base_ts + 0)    * 1000),
            (13.0822, 80.2703, 12.0, 6.0,   0.2,   "gps",    (base_ts + 30)   * 1000),
            (13.0825, 80.2705, 10.0, 6.0,   0.5,   "gps",    (base_ts + 60)   * 1000),
            (13.0827, 80.2707, 8.0,  6.0,   0.4,   "gps",    (base_ts + 90)   * 1000),
            (13.0829, 80.2709, 9.0,  6.0,   0.3,   "network", (base_ts + 120) * 1000),
        ]

        # SPOOFED Bengaluru records (during mock location window)
        # Bengaluru: 12.9716°N, 77.5946°E
        # These appear ~1800 seconds after base — physically impossible from Chennai
        spoofed_records = [
            (12.9716, 77.5946, 5.0,  920.0, 0.0, "gps",  (base_ts + 1800) * 1000),
            (12.9720, 77.5950, 4.0,  920.0, 0.1, "gps",  (base_ts + 1830) * 1000),
            (12.9718, 77.5948, 6.0,  920.0, 0.0, "gps",  (base_ts + 1860) * 1000),
            (12.9715, 77.5944, 5.5,  920.0, 0.2, "gps",  (base_ts + 1890) * 1000),
            (12.9722, 77.5952, 4.0,  920.0, 0.0, "gps",  (base_ts + 1920) * 1000),
        ]

        # Return to Chennai (post-spoofing)
        return_records = [
            (13.0828, 80.2706, 11.0, 6.0, 0.3, "gps",    (base_ts + 3700) * 1000),
            (13.0830, 80.2708, 10.0, 6.0, 0.2, "network", (base_ts + 3730) * 1000),
        ]

        all_gps_records = genuine_records + spoofed_records + return_records
        cur.executemany(
            "INSERT INTO locations (latitude, longitude, accuracy, altitude, speed, provider, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            all_gps_records
        )
        conn.commit()
        conn.close()

        # ── netconn.db (Cell Tower Records) ──────────────────────────────
        # Cell towers stay in Chennai throughout — this is the contradiction
        netconn_path = os.path.join(gms_db_dir, "netconn.db")
        conn = sqlite3.connect(netconn_path)
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cell_scan_results (
                _id       INTEGER PRIMARY KEY AUTOINCREMENT,
                mcc       INTEGER,
                mnc       INTEGER,
                lac       INTEGER,
                cid       INTEGER,
                signal    INTEGER,
                timestamp INTEGER NOT NULL
            )
        """)

        # All cell tower records are Chennai towers (MCC=404 India, MNC=20 Vodafone)
        # CID values are from Chennai area — unchanged during "Bengaluru" GPS window
        cell_records = [
            (404, 20, 8001, 28741, -75, (base_ts + 0)    * 1000),
            (404, 20, 8001, 28742, -78, (base_ts + 600)  * 1000),
            (404, 20, 8001, 28741, -72, (base_ts + 1800) * 1000),  # During spoofing!
            (404, 20, 8001, 28743, -80, (base_ts + 1860) * 1000),  # During spoofing!
            (404, 20, 8001, 28741, -76, (base_ts + 2400) * 1000),
            (404, 20, 8001, 28742, -74, (base_ts + 3600) * 1000),
        ]

        cur.executemany(
            "INSERT INTO cell_scan_results (mcc, mnc, lac, cid, signal, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            cell_records
        )
        conn.commit()
        conn.close()

        # ── location_cache.db (Fused Location Provider cache) ────────────
        cache_path = os.path.join(gms_db_dir, "location_cache.db")
        conn = sqlite3.connect(cache_path)
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS fused_locations (
                _id         INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude    REAL,
                longitude   REAL,
                accuracy    REAL,
                provider    TEXT,
                extras      TEXT,
                timestamp   INTEGER
            )
        """)

        # Fused provider blends GPS + network — will show spoofed GPS during window
        fused_records = [
            (13.0827, 80.2707, 10.0, "fused", "network+gps",  (base_ts + 100)  * 1000),
            (12.9716, 77.5946, 5.0,  "fused", "gps",          (base_ts + 1800) * 1000),
            (12.9720, 77.5950, 5.0,  "fused", "gps",          (base_ts + 1860) * 1000),
            (13.0829, 80.2708, 11.0, "fused", "network+gps",  (base_ts + 3700) * 1000),
        ]

        cur.executemany(
            "INSERT INTO fused_locations (latitude, longitude, accuracy, provider, extras, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            fused_records
        )
        conn.commit()
        conn.close()

        # ── da_destination_history.db (Google Maps destinations) ─────────
        maps_dir = os.path.join(root, "data/data/com.google.android.apps.maps/databases")
        os.makedirs(maps_dir, exist_ok=True)

        dest_path = os.path.join(maps_dir, "da_destination_history.db")
        conn = sqlite3.connect(dest_path)
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS destination_history (
                _id         INTEGER PRIMARY KEY AUTOINCREMENT,
                dest_lat    REAL,
                dest_lng    REAL,
                dest_name   TEXT,
                timestamp   INTEGER
            )
        """)

        dest_records = [
            (12.9716, 77.5946, "MG Road, Bengaluru, Karnataka", (base_ts + 1750) * 1000),
            (13.0827, 80.2707, "Anna Salai, Chennai, Tamil Nadu",  (base_ts + 50)   * 1000),
        ]

        cur.executemany(
            "INSERT INTO destination_history (dest_lat, dest_lng, dest_name, timestamp) "
            "VALUES (?, ?, ?, ?)",
            dest_records
        )
        conn.commit()
        conn.close()

        # ── logcat_dump.txt ───────────────────────────────────────────────
        # Contains mock location provider log lines
        logcat_content = (
            f"03-15 09:{(1740//60):02d}:{(1740%60):02d}.123  1234  5678 I MockLocationProvider: "
            f"setTestProviderLocation: provider=gps lat=12.9716 lng=77.5946\n"
            f"03-15 09:{(1800//60):02d}:{(1800%60):02d}.456  1234  5678 D LocationManagerService: "
            f"Mock provider enabled for gps by com.lexa.fakegps\n"
            f"03-15 09:44:02.789  1234  5678 D LocationManagerService: "
            f"Mock provider disabled for gps\n"
        )
        with open(os.path.join(root, "logcat_dump.txt"), "w") as f:
            f.write(logcat_content)

        # ── dumpsys_location.txt ──────────────────────────────────────────
        dumpsys_content = (
            "Location Manager State:\n"
            "  Mock Location Providers: []\n"
            "  Last Known Locations:\n"
            "    gps: Location[gps 13.082700,80.270700 acc=10 et=+1s]\n"
            "  Providers:\n"
            "    network (enabled)\n"
            "    gps (enabled)\n"
        )
        with open(os.path.join(root, "dumpsys_location.txt"), "w") as f:
            f.write(dumpsys_content)

        # ── Write hash log for demo artefacts ─────────────────────────────
        self._write_hash_log()
