#!/usr/bin/env python3
"""
=============================================================================
Module : detector.py
Purpose: Core spoofing detection engine. Implements five independent
         detection checks, each producing a structured result with a
         'flagged' boolean, a human-readable 'summary', and 'evidence'
         list for the forensic report.
=============================================================================

Detection Checks:
  1. mock_location_check      — Developer Options + mock location setting
  2. spoofing_app_check       — Known spoofing apps in installed package list
  3. impossible_travel_check  — GPS jump exceeding speed threshold
  4. cell_gps_contradiction   — Cell towers vs GPS coordinates disagree
  5. logcat_mock_check        — Logcat contains mock location provider events

All checks are independent. The overall verdict requires multiple flags.
"""

import math
import datetime


# ─────────────────────────────────────────────────────────────────────────────
# HAVERSINE DISTANCE CALCULATOR
# ─────────────────────────────────────────────────────────────────────────────

def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Calculate the great-circle distance between two GPS coordinates
    using the Haversine formula. Returns distance in kilometres.

    This accounts for Earth's curvature, providing accurate results
    for the inter-city distances encountered in spoofing detection.
    """
    R = 6371.0  # Earth radius in kilometres

    # Convert decimal degrees to radians
    phi1    = math.radians(lat1)
    phi2    = math.radians(lat2)
    d_phi   = math.radians(lat2 - lat1)
    d_lambda= math.radians(lng2 - lng1)

    a = (math.sin(d_phi   / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# ─────────────────────────────────────────────────────────────────────────────
# CELL TOWER GEOGRAPHIC RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

# Simplified CID-to-area mapping for demonstration purposes.
# In a real investigation this would query OpenCelliD or GSMA databases.
CELL_TOWER_REGIONS = {
    # Chennai area towers (Tamil Nadu, India)
    28741: ("Chennai", 13.0827, 80.2707),
    28742: ("Chennai", 13.0900, 80.2750),
    28743: ("Chennai", 13.0750, 80.2650),
    28744: ("Chennai", 13.0800, 80.2800),
    # Bengaluru area towers (Karnataka, India)
    41001: ("Bengaluru", 12.9716, 77.5946),
    41002: ("Bengaluru", 12.9780, 77.6000),
    41003: ("Bengaluru", 12.9650, 77.5900),
}


def resolve_cell_region(cid: int) -> tuple:
    """
    Resolve a cell tower CID to a region name and approximate lat/lng.
    Returns (region_name, lat, lng) or ('Unknown', None, None).
    """
    return CELL_TOWER_REGIONS.get(cid, ("Unknown", None, None))


# ─────────────────────────────────────────────────────────────────────────────
# SPOOFING DETECTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SpoofingDetector:
    """
    Runs all spoofing detection checks against parsed artefact data.

    Args:
        parsed_data        : Dictionary returned by ArtifactParser.parse_all()
        speed_threshold_kmh: Travel speed above which GPS jump is flagged
        verbose            : Print debug info when True
    """

    def __init__(
        self,
        parsed_data: dict,
        speed_threshold_kmh: float = 900.0,
        verbose: bool = False
    ):
        self.data      = parsed_data
        self.threshold = speed_threshold_kmh
        self.verbose   = verbose

    def _dbg(self, msg: str):
        if self.verbose:
            print(f"    [DBG:DETECT] {msg}")

    # ─────────────────────────────────────────────────────────────────────────
    # MASTER: Run all checks
    # ─────────────────────────────────────────────────────────────────────────

    def run_all_checks(self) -> dict:
        """
        Execute all five detection checks.
        Returns a dictionary: { check_name → result_dict }

        Each result_dict contains:
          flagged  : bool   — True if this check detected spoofing indicator
          summary  : str    — One-line human-readable result
          evidence : list   — List of evidence strings for the report
        """
        results = {}

        results["Mock Location Setting"]    = self.check_mock_location_setting()
        results["Spoofing App Installed"]   = self.check_spoofing_app()
        results["Impossible Travel Speed"]  = self.check_impossible_travel()
        results["Cell Tower Contradiction"] = self.check_cell_gps_contradiction()
        results["Logcat Mock Events"]       = self.check_logcat_mock_events()

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 1: Mock Location Setting Active
    # ─────────────────────────────────────────────────────────────────────────

    def check_mock_location_setting(self) -> dict:
        """
        Check whether Developer Options were enabled and whether a mock
        location application was designated in the secure settings.

        Forensic significance:
          Developer Options are off by default. Enablement requires deliberate
          action (7-tap sequence). Mock location app designation is a direct
          prerequisite for app-level GPS spoofing. Timestamps show when this
          occurred relative to the spoofed location records.
        """
        evidence = []
        flagged  = False

        if self.data.get('mock_location_enabled'):
            flagged = True
            evidence.append("Developer Options were enabled on this device.")

        dev_ts = self.data.get('developer_options_ts')
        if dev_ts:
            evidence.append(
                f"Developer Options enablement timestamp: "
                f"{_epoch_ms_str(dev_ts)}"
            )

        mock_pkg = self.data.get('mock_location_package')
        if mock_pkg:
            flagged = True
            evidence.append(
                f"Mock Location App designated: '{mock_pkg}'"
            )

        mock_ts = self.data.get('mock_location_set_ts')
        if mock_ts:
            evidence.append(
                f"Mock location setting modification timestamp: "
                f"{_epoch_ms_str(mock_ts)}"
            )

        if not flagged:
            summary  = "No mock location setting detected."
        elif mock_pkg:
            summary  = f"FLAGGED — Mock location app '{mock_pkg}' was active."
        else:
            summary  = "FLAGGED — Developer Options enabled (mock location may have been used)."

        return {"flagged": flagged, "summary": summary, "evidence": evidence}

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 2: Known Spoofing Application Installed
    # ─────────────────────────────────────────────────────────────────────────

    def check_spoofing_app(self) -> dict:
        """
        Check installed package list against the known spoofing app database.

        Forensic significance:
          The presence of a known spoofing application — even if now uninstalled —
          leaves residual artefacts. Install timestamp clustering with mock
          location setting activation constitutes behavioural pattern evidence.
        """
        apps     = self.data.get('spoofing_apps', [])
        evidence = []
        flagged  = bool(apps)

        for app in apps:
            entry = (
                f"Package: {app['package']}  |  "
                f"Name: {app['name']}"
            )
            if app.get('install_ts'):
                entry += f"  |  Installed: {_epoch_ms_str(app['install_ts'])}"
            evidence.append(entry)

        if flagged:
            summary = (
                f"FLAGGED — {len(apps)} known spoofing application(s) found: "
                + ", ".join(a['package'] for a in apps)
            )
        else:
            summary = "No known GPS spoofing applications detected in package list."

        return {"flagged": flagged, "summary": summary, "evidence": evidence}

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 3: Impossible Travel Speed Detection
    # ─────────────────────────────────────────────────────────────────────────

    def check_impossible_travel(self) -> dict:
        """
        Analyse consecutive GPS records for physically impossible travel speed.

        Method:
          For each pair of consecutive GPS records:
            1. Compute Haversine distance (km)
            2. Compute time delta (hours)
            3. Compute implied speed = distance / time
            4. Flag if speed > threshold (default 900 km/h)

        Forensic significance:
          A GPS coordinate jump of 347 km (Chennai → Bengaluru) in under
          60 seconds implies ~20,000+ km/h — physically impossible for any
          civilian transport and definitive of fabricated coordinates.
        """
        records  = self.data.get('gps_records', [])
        evidence = []
        flagged  = False
        worst_speed = 0.0
        worst_pair  = None

        if len(records) < 2:
            return {
                "flagged"  : False,
                "summary"  : "Insufficient GPS records for travel speed analysis.",
                "evidence" : []
            }

        for i in range(len(records) - 1):
            r1 = records[i]
            r2 = records[i + 1]

            # Time delta in hours
            ts_delta_ms  = r2['ts_ms'] - r1['ts_ms']
            if ts_delta_ms <= 0:
                continue
            ts_delta_hrs = ts_delta_ms / 1000.0 / 3600.0

            # Haversine distance in km
            dist_km = haversine_km(r1['lat'], r1['lng'], r2['lat'], r2['lng'])

            # Implied speed
            if ts_delta_hrs > 0:
                speed_kmh = dist_km / ts_delta_hrs
            else:
                speed_kmh = 0.0

            self._dbg(
                f"GPS pair {i}→{i+1}: dist={dist_km:.1f}km  "
                f"time={ts_delta_ms/1000:.1f}s  speed={speed_kmh:.0f} km/h"
            )

            if speed_kmh > self.threshold:
                flagged = True

                if speed_kmh > worst_speed:
                    worst_speed = speed_kmh
                    worst_pair  = (r1, r2, dist_km, ts_delta_ms / 1000.0, speed_kmh)

                evidence.append(
                    f"GPS jump detected: "
                    f"({r1['lat']:.4f},{r1['lng']:.4f}) → ({r2['lat']:.4f},{r2['lng']:.4f})  |  "
                    f"Distance: {dist_km:.1f} km  |  "
                    f"Time delta: {ts_delta_ms/1000:.1f} s  |  "
                    f"Implied speed: {speed_kmh:,.0f} km/h  |  "
                    f"Threshold: {self.threshold:.0f} km/h  |  "
                    f"At: {_epoch_ms_str(r2['ts_ms'])}"
                )

        if flagged and worst_pair:
            r1, r2, dist, dt, speed = worst_pair
            summary = (
                f"FLAGGED — Maximum implied speed: {speed:,.0f} km/h "
                f"({dist:.1f} km in {dt:.1f} s). "
                f"Threshold: {self.threshold:.0f} km/h. Physically impossible."
            )
        else:
            summary = (
                f"No impossible travel detected. All GPS transitions within "
                f"{self.threshold:.0f} km/h threshold."
            )

        return {"flagged": flagged, "summary": summary, "evidence": evidence}

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 4: Cell Tower vs GPS Contradiction
    # ─────────────────────────────────────────────────────────────────────────

    def check_cell_gps_contradiction(self) -> dict:
        """
        Cross-correlate cell tower records with GPS records at overlapping
        timestamps to identify geographic contradictions.

        Method:
          For each GPS record, find the nearest-timestamp cell tower record.
          Resolve the cell tower CID to a geographic region.
          If the GPS coordinate is more than MAX_HONEST_DIST_KM away from
          the cell tower's known region, flag as contradiction.

        Forensic significance:
          Cell tower location cannot be spoofed by any app-level method.
          A device connected to a Chennai cell tower while GPS reports
          Bengaluru coordinates is an irreconcilable physical contradiction.
        """
        # Maximum honest distance: a cell tower covers ~5-35 km radius.
        # We use 50 km as a generous threshold to avoid false positives
        # from large rural cells. Inter-city distances (>300 km) will be caught.
        MAX_HONEST_DIST_KM = 50.0

        gps_records  = self.data.get('gps_records',  [])
        cell_records = self.data.get('cell_records', [])
        evidence     = []
        flagged      = False

        if not gps_records or not cell_records:
            return {
                "flagged"  : False,
                "summary"  : "Insufficient data for cell/GPS cross-correlation.",
                "evidence" : []
            }

        # For each GPS record, find the cell record with nearest timestamp
        for gps in gps_records:
            gps_ts = gps['ts_ms']

            # Find closest cell record by timestamp
            closest_cell = min(
                cell_records,
                key=lambda c: abs(c['ts_ms'] - gps_ts)
            )

            # Only compare if within a 5-minute window
            time_gap_s = abs(closest_cell['ts_ms'] - gps_ts) / 1000.0
            if time_gap_s > 300:
                continue

            cell_region, cell_lat, cell_lng = resolve_cell_region(closest_cell['cid'])

            # Skip if cell tower is unknown (cannot resolve region)
            if cell_lat is None:
                continue

            # Distance between GPS coordinate and cell tower region
            dist_km = haversine_km(gps['lat'], gps['lng'], cell_lat, cell_lng)

            self._dbg(
                f"GPS ({gps['lat']:.4f},{gps['lng']:.4f}) vs "
                f"Cell CID {closest_cell['cid']} ({cell_region}) "
                f"dist={dist_km:.1f} km  gap={time_gap_s:.1f}s"
            )

            if dist_km > MAX_HONEST_DIST_KM:
                flagged = True
                evidence.append(
                    f"CONTRADICTION at {_epoch_ms_str(gps_ts)}: "
                    f"GPS reports ({gps['lat']:.4f},{gps['lng']:.4f})  |  "
                    f"Cell tower CID={closest_cell['cid']} resolves to '{cell_region}' "
                    f"({cell_lat:.4f},{cell_lng:.4f})  |  "
                    f"Separation: {dist_km:.1f} km  |  "
                    f"Time gap between records: {time_gap_s:.1f} s"
                )

        if flagged:
            summary = (
                f"FLAGGED — {len(evidence)} GPS/cell tower geographic contradictions detected. "
                f"Device GPS reports locations inconsistent with simultaneously active cell towers."
            )
        else:
            summary = "GPS coordinates are consistent with cell tower geographic regions."

        return {"flagged": flagged, "summary": summary, "evidence": evidence}

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 5: Logcat Mock Location Events
    # ─────────────────────────────────────────────────────────────────────────

    def check_logcat_mock_events(self) -> dict:
        """
        Check the logcat dump for mock location provider system events.

        These log events are generated by the Android LocationManagerService
        and are not under application control — they cannot be suppressed
        by the spoofing application itself (only a root-level log wiper
        could remove them post-hoc).

        Key log events:
          - 'setTestProviderLocation' — mock coordinates being injected
          - 'Mock provider enabled'   — mock provider activation
          - 'Mock provider disabled'  — mock provider deactivation
        """
        events   = self.data.get('logcat_mock_events', [])
        evidence = []
        flagged  = bool(events)

        for event in events:
            evidence.append(f"[{event['ts_str']}] {event['line']}")

        if flagged:
            summary = (
                f"FLAGGED — {len(events)} mock location provider event(s) found in logcat. "
                f"System-level evidence of active GPS spoofing."
            )
        else:
            summary = "No mock location events found in logcat dump."

        return {"flagged": flagged, "summary": summary, "evidence": evidence}

    # ─────────────────────────────────────────────────────────────────────────
    # OVERALL VERDICT
    # ─────────────────────────────────────────────────────────────────────────

    def get_overall_verdict(self, results: dict) -> str:
        """
        Produce an overall spoofing verdict based on how many independent
        checks were flagged.

        Thresholds:
          0 flags  → No Evidence of Spoofing
          1 flag   → Inconclusive — Possible Innocent Explanation
          2 flags  → Suspicious — Further Investigation Warranted
          3+ flags → Strong Evidence of GPS Spoofing
        """
        flag_count = sum(1 for r in results.values() if r['flagged'])

        if flag_count == 0:
            return "NO EVIDENCE OF GPS SPOOFING DETECTED"
        elif flag_count == 1:
            return "INCONCLUSIVE — ONE INDICATOR PRESENT (possible innocent explanation)"
        elif flag_count == 2:
            return "SUSPICIOUS — TWO INDEPENDENT INDICATORS DETECTED"
        else:
            return (
                f"STRONG EVIDENCE OF GPS SPOOFING — "
                f"{flag_count}/5 INDEPENDENT INDICATORS CONFIRMED"
            )


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def _epoch_ms_str(ts_ms: int) -> str:
    """Convert Unix epoch milliseconds to UTC string."""
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"
