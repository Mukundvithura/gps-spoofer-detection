#!/usr/bin/env python3
"""
=============================================================================
Module : timeline.py
Purpose: Merge all forensic artefact timestamps into a single unified
         chronological event timeline, annotating suspicious events.
=============================================================================

Event sources merged:
  1. GPS location records        (herrevad.db / location_cache.db)
  2. Cell tower scan records     (netconn.db)
  3. Google Maps destinations    (da_destination_history.db)
  4. Mock location settings      (settings_secure.xml)
  5. Spoofing app install events (package_list)
  6. Logcat mock location events (logcat_dump.txt)
  7. Detection engine findings   (detector.py results)

Each event in the timeline has:
  ts_ms       : int     — Unix timestamp milliseconds
  ts_utc      : str     — Human-readable UTC string
  source      : str     — Artefact source identifier
  event_type  : str     — Category of event
  description : str     — Human-readable event description
  suspicious  : bool    — True if this event was flagged by the detector
  lat         : float   — Latitude (if applicable)
  lng         : float   — Longitude (if applicable)
"""

import datetime
from detector import haversine_km


# ─────────────────────────────────────────────────────────────────────────────
# TIMELINE ENGINE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class TimelineEngine:
    """
    Constructs a unified forensic event timeline from all parsed artefacts
    and detection results.

    Args:
        parsed_data      : Output of ArtifactParser.parse_all()
        detection_results: Output of SpoofingDetector.run_all_checks()
        verbose          : Print debug output when True
    """

    def __init__(
        self,
        parsed_data: dict,
        detection_results: dict,
        verbose: bool = False
    ):
        self.data       = parsed_data
        self.results    = detection_results
        self.verbose    = verbose
        self._events    = []

    def _dbg(self, msg: str):
        if self.verbose:
            print(f"    [DBG:TIMELINE] {msg}")

    # ─────────────────────────────────────────────────────────────────────────
    # MASTER: Build complete timeline
    # ─────────────────────────────────────────────────────────────────────────

    def build_timeline(self) -> list:
        """
        Collect events from all sources, sort by timestamp ascending,
        and annotate suspicious events.

        Returns:
            List of event dicts sorted by ts_ms.
        """
        self._events = []

        self._ingest_settings_events()
        self._ingest_spoofing_app_events()
        self._ingest_gps_records()
        self._ingest_cell_records()
        self._ingest_map_destinations()
        self._ingest_logcat_events()
        self._mark_suspicious_events()

        # Sort all events chronologically
        self._events.sort(key=lambda e: e['ts_ms'])

        self._dbg(f"Timeline built: {len(self._events)} total events")
        return self._events

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: Settings events (mock location setting timestamps)
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_settings_events(self):
        """Add settings-change events to the timeline."""

        dev_ts = self.data.get('developer_options_ts')
        if dev_ts:
            self._add_event(
                ts_ms      = dev_ts,
                source     = "settings_global.xml",
                event_type = "DEVELOPER_OPTIONS_ENABLED",
                description= "Developer Options were enabled on this device.",
                lat=None, lng=None
            )

        mock_ts  = self.data.get('mock_location_set_ts')
        mock_pkg = self.data.get('mock_location_package')
        if mock_ts:
            desc = f"Mock Location App designated: '{mock_pkg}'" if mock_pkg \
                   else "Mock location setting was modified."
            self._add_event(
                ts_ms      = mock_ts,
                source     = "settings_secure.xml",
                event_type = "MOCK_LOCATION_SET",
                description= desc,
                lat=None, lng=None
            )

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: Spoofing app install events
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_spoofing_app_events(self):
        """Add spoofing application install events to the timeline."""
        for app in self.data.get('spoofing_apps', []):
            if app.get('install_ts'):
                self._add_event(
                    ts_ms      = app['install_ts'],
                    source     = "package_list.txt",
                    event_type = "SPOOFING_APP_INSTALLED",
                    description= (
                        f"GPS spoofing application installed: "
                        f"{app['name']} ({app['package']})"
                    ),
                    lat=None, lng=None
                )

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: GPS location records
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_gps_records(self):
        """Add GPS location records to the timeline."""
        for rec in self.data.get('gps_records', []):
            provider = rec.get('provider', 'gps')
            accuracy = rec.get('accuracy', 0)
            self._add_event(
                ts_ms      = rec['ts_ms'],
                source     = "herrevad.db",
                event_type = "GPS_LOCATION",
                description= (
                    f"GPS fix: ({rec['lat']:.4f}, {rec['lng']:.4f})  "
                    f"Provider={provider}  Accuracy={accuracy:.1f}m"
                ),
                lat=rec['lat'], lng=rec['lng']
            )

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: Cell tower records
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_cell_records(self):
        """Add cell tower scan records to the timeline."""
        for rec in self.data.get('cell_records', []):
            self._add_event(
                ts_ms      = rec['ts_ms'],
                source     = "netconn.db",
                event_type = "CELL_TOWER_SCAN",
                description= (
                    f"Cell tower: MCC={rec['mcc']}  MNC={rec['mnc']}  "
                    f"LAC={rec['lac']}  CID={rec['cid']}  Signal={rec['signal']} dBm"
                ),
                lat=None, lng=None
            )

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: Google Maps destination history
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_map_destinations(self):
        """Add Google Maps navigation destinations to the timeline."""
        for dest in self.data.get('map_destinations', []):
            self._add_event(
                ts_ms      = dest['ts_ms'],
                source     = "da_destination_history.db",
                event_type = "MAPS_DESTINATION",
                description= (
                    f"Google Maps navigation to: '{dest['name']}'  "
                    f"({dest['lat']:.4f}, {dest['lng']:.4f})"
                ),
                lat=dest['lat'], lng=dest['lng']
            )

    # ─────────────────────────────────────────────────────────────────────────
    # INGEST: Logcat mock location events
    # ─────────────────────────────────────────────────────────────────────────

    def _ingest_logcat_events(self):
        """
        Add logcat mock provider events to the timeline.
        These use logcat's MM-DD HH:MM:SS format — we convert to a
        synthetic epoch timestamp using the current year for display.
        Without a year in logcat, we annotate with the string timestamp.
        """
        for event in self.data.get('logcat_mock_events', []):
            # Attempt to parse logcat timestamp (format: MM-DD HH:MM:SS.mmm)
            ts_str = event.get('ts_str', 'unknown')
            ts_ms  = _parse_logcat_timestamp(ts_str)

            self._add_event(
                ts_ms      = ts_ms if ts_ms else 0,
                source     = "logcat_dump.txt",
                event_type = "MOCK_LOCATION_LOGCAT",
                description= f"Logcat: {event['line'][:120]}",
                lat=None, lng=None
            )

    # ─────────────────────────────────────────────────────────────────────────
    # ANNOTATE: Mark suspicious events
    # ─────────────────────────────────────────────────────────────────────────

    def _mark_suspicious_events(self):
        """
        Post-process all events and mark those that align with a detected
        spoofing indicator as suspicious=True.

        Suspicious event criteria:
          - All MOCK_LOCATION_SET events
          - All SPOOFING_APP_INSTALLED events
          - All MOCK_LOCATION_LOGCAT events
          - All DEVELOPER_OPTIONS_ENABLED events
          - GPS_LOCATION events during the spoofing window
          - MAPS_DESTINATION events that correlate with a spoofed GPS period
        """
        # Determine the spoofing window from GPS impossible-travel results
        spoof_window_start = None
        spoof_window_end   = None

        gps_records = self.data.get('gps_records', [])
        if len(gps_records) >= 2:
            for i in range(len(gps_records) - 1):
                r1 = gps_records[i]
                r2 = gps_records[i + 1]
                ts_delta_s = (r2['ts_ms'] - r1['ts_ms']) / 1000.0
                if ts_delta_s <= 0:
                    continue
                dist_km    = haversine_km(r1['lat'], r1['lng'], r2['lat'], r2['lng'])
                speed_kmh  = (dist_km / (ts_delta_s / 3600.0)) if ts_delta_s > 0 else 0

                if speed_kmh > 900:
                    # The spoofing window starts at the jump timestamp
                    if spoof_window_start is None:
                        spoof_window_start = r1['ts_ms']
                    spoof_window_end = r2['ts_ms'] + (30 * 60 * 1000)  # +30 min buffer

        # Annotate each event
        for event in self._events:
            event_type = event['event_type']

            # These event types are inherently suspicious
            if event_type in (
                'MOCK_LOCATION_SET',
                'SPOOFING_APP_INSTALLED',
                'MOCK_LOCATION_LOGCAT',
                'DEVELOPER_OPTIONS_ENABLED'
            ):
                event['suspicious'] = True
                continue

            # GPS or Maps events during the spoofing window
            if spoof_window_start and event_type in ('GPS_LOCATION', 'MAPS_DESTINATION'):
                if spoof_window_start <= event['ts_ms'] <= (spoof_window_end or 0):
                    event['suspicious'] = True
                    continue

            # Default: not suspicious
            event.setdefault('suspicious', False)

    # ─────────────────────────────────────────────────────────────────────────
    # HELPER: Add event to internal list
    # ─────────────────────────────────────────────────────────────────────────

    def _add_event(
        self,
        ts_ms: int,
        source: str,
        event_type: str,
        description: str,
        lat: float,
        lng: float
    ):
        """Append a structured event dictionary to the internal event list."""
        if ts_ms is None or ts_ms <= 0:
            ts_utc = "UNKNOWN TIME"
        else:
            try:
                dt     = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
                ts_utc = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                ts_utc = f"(ts_ms={ts_ms})"

        self._events.append({
            'ts_ms'      : ts_ms or 0,
            'ts_utc'     : ts_utc,
            'source'     : source,
            'event_type' : event_type,
            'description': description,
            'suspicious' : False,  # Will be updated by _mark_suspicious_events
            'lat'        : lat,
            'lng'        : lng,
        })


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: Parse logcat timestamp string to epoch ms
# ─────────────────────────────────────────────────────────────────────────────

def _parse_logcat_timestamp(ts_str: str) -> int:
    """
    Attempt to parse a logcat timestamp (MM-DD HH:MM:SS.mmm) into
    Unix epoch milliseconds. Uses current year since logcat omits year.
    Returns 0 on failure.
    """
    try:
        year = datetime.datetime.utcnow().year
        # Handle both 'MM-DD HH:MM:SS.mmm' and 'MM-DD HH:MM:SS'
        parts = ts_str.split('.')
        base  = parts[0].strip()
        ms    = int(parts[1]) if len(parts) > 1 else 0

        dt = datetime.datetime.strptime(f"{year}-{base}", "%Y-%m-%d %H:%M:%S")
        epoch_s  = int(dt.timestamp())
        epoch_ms = epoch_s * 1000 + ms
        return epoch_ms
    except Exception:
        return 0
