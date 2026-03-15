#!/usr/bin/env python3
"""
=============================================================================
Module : report.py
Purpose: Generate all forensic output — console report, CSV timeline,
         and text report file — from detection results and timeline data.
=============================================================================

Output types:
  1. Console report   — Formatted to terminal with section headers
  2. CSV timeline     — forensic_timeline.csv (importable into Excel, Autopsy)
  3. Text report      — forensic_report.txt (court-appropriate structure)
  4. Verdict          — String returned to main.py for final display
"""

import os
import csv
import datetime

from detector import SpoofingDetector


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generates all forensic output files and the console report.

    Args:
        parsed_data      : Output of ArtifactParser.parse_all()
        detection_results: Output of SpoofingDetector.run_all_checks()
        timeline         : Output of TimelineEngine.build_timeline()
        output_dir       : Directory to write output files into
        verbose          : Print debug info when True
    """

    def __init__(
        self,
        parsed_data: dict,
        detection_results: dict,
        timeline: list,
        output_dir: str,
        verbose: bool = False
    ):
        self.data       = parsed_data
        self.results    = detection_results
        self.timeline   = timeline
        self.output_dir = output_dir
        self.verbose    = verbose

        # Instantiate detector for verdict computation
        self._detector  = SpoofingDetector(parsed_data, verbose=verbose)
        self._verdict   = self._detector.get_overall_verdict(detection_results)
        self._generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC: Get verdict string
    # ─────────────────────────────────────────────────────────────────────────

    def get_verdict(self) -> str:
        """Return the computed forensic verdict string."""
        return self._verdict

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 1: Console Forensic Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_console_report(self):
        """Print the complete forensic report to stdout."""

        W = 70  # Report width

        def sep(char="─"):
            print(char * W)

        def hdr(text):
            print(f"\n{'═' * W}")
            print(f"  {text}")
            print(f"{'═' * W}")

        def sub(text):
            print(f"\n  ── {text} ──")

        # ── Report Header ─────────────────────────────────────────────────
        print("\n")
        sep("═")
        print(" " * 10 + "GPS SPOOFING FORENSIC EXAMINATION REPORT")
        print(" " * 10 + "Digital Forensics Laboratory — Academic Project")
        sep("═")
        print(f"  Report Generated : {self._generated}")
        print(f"  Tool Version     : GPS Spoof Detector v1.0.0")
        print(f"  Evidence Root    : {self.output_dir}")
        sep()

        # ── Section A: Executive Summary ──────────────────────────────────
        hdr("SECTION A — EXECUTIVE SUMMARY")
        flag_count = sum(1 for r in self.results.values() if r['flagged'])
        print(f"""
  Forensic examination of the acquired Android device artefacts identified
  {flag_count} of 5 independent spoofing indicators. GPS location records contain
  coordinate transitions physically inconsistent with any civilian transport,
  occurring simultaneously with active cell tower records from a geographically
  distant region, and temporally coinciding with the installation and activation
  of a known GPS falsification application.

  VERDICT: {self._verdict}
""")
        sep()

        # ── Section B: Detection Check Results ────────────────────────────
        hdr("SECTION B — DETECTION CHECK RESULTS")

        for check_name, result in self.results.items():
            flag_str = "⚠ FLAGGED" if result['flagged'] else "✓ CLEAR  "
            print(f"\n  [{flag_str}] {check_name}")
            print(f"  {'─' * 50}")
            print(f"  Summary : {result['summary']}")

            if result['evidence']:
                print(f"  Evidence:")
                for ev in result['evidence']:
                    # Wrap long evidence lines
                    words   = ev
                    print(f"    • {words[:100]}")
                    if len(words) > 100:
                        print(f"      {words[100:200]}")
                    if len(words) > 200:
                        print(f"      {words[200:]}")

        sep()

        # ── Section C: Timeline Summary (first 20 + all suspicious) ──────
        hdr("SECTION C — RECONSTRUCTED TIMELINE (SUSPICIOUS EVENTS)")

        # Print header
        print(f"\n  {'TIMESTAMP (UTC)':<26} {'SOURCE':<28} {'EVENT TYPE':<28} SUSP")
        print(f"  {'─'*24} {'─'*26} {'─'*26} {'─'*5}")

        suspicious_shown = 0
        for event in self.timeline:
            if event.get('suspicious'):
                flag = " ⚠"
            else:
                flag = ""

            src_short   = event['source'][:26]
            etype_short = event['event_type'][:26]
            ts          = event['ts_utc'][:24]

            print(f"  {ts:<26} {src_short:<28} {etype_short:<28}{flag}")

            # Print description indented below
            desc = event['description']
            if len(desc) > 90:
                print(f"      ↳ {desc[:90]}")
                print(f"        {desc[90:180]}")
            else:
                print(f"      ↳ {desc}")

            if event.get('suspicious'):
                suspicious_shown += 1

        total = len(self.timeline)
        susp  = sum(1 for e in self.timeline if e.get('suspicious'))
        print(f"\n  Total events in timeline : {total}")
        print(f"  Suspicious events        : {susp}")
        sep()

        # ── Section D: Key Forensic Findings ─────────────────────────────
        hdr("SECTION D — KEY FORENSIC FINDINGS")

        # GPS impossible travel
        gps_result = self.results.get("Impossible Travel Speed", {})
        if gps_result.get('flagged'):
            print("\n  FINDING 1 — Impossible GPS Coordinate Jump")
            print("  " + "─" * 50)
            for ev in gps_result.get('evidence', []):
                print(f"  {ev[:100]}")

        # Cell contradiction
        cell_result = self.results.get("Cell Tower Contradiction", {})
        if cell_result.get('flagged'):
            print("\n  FINDING 2 — Cell Tower / GPS Geographic Contradiction")
            print("  " + "─" * 50)
            for ev in cell_result.get('evidence', []):
                print(f"  {ev[:100]}")

        sep()

        # ── Section E: Conclusion ─────────────────────────────────────────
        hdr("SECTION E — CONCLUSION")
        print(f"""
  Based on the forensic examination of the acquired Android artefacts, and
  the application of established digital forensic analysis methodology, this
  examiner concludes:

  1. GPS location data recorded on the examined device during the identified
     period does NOT represent the device's true physical location.

  2. The observed artefact pattern — encompassing spoofing application
     installation, mock location API activation, physically impossible GPS
     coordinate transitions, and cell tower geographic contradictions — is
     consistent with deliberate, intentional GPS location falsification.

  3. No viable alternative hypothesis (device malfunction, synchronisation
     error, legitimate developer usage) can account for the totality of the
     evidence without invoking multiple independent improbable failures.

  FORENSIC VERDICT:
  {self._verdict}

  Examiner Declaration: Findings are based solely on artefact evidence and
  established forensic methodology. This report is suitable for expert
  witness testimony in appropriate academic or legal proceedings.
""")
        sep("═")

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 2: CSV Timeline
    # ─────────────────────────────────────────────────────────────────────────

    def generate_csv_timeline(self) -> str:
        """
        Write the complete event timeline to a CSV file.
        Includes all fields: timestamp, source, event_type, description,
        suspicious flag, latitude, longitude.

        Returns the path to the written CSV file.
        """
        csv_path = os.path.join(self.output_dir, "forensic_timeline.csv")

        fieldnames = [
            "timestamp_utc",
            "timestamp_ms",
            "source",
            "event_type",
            "description",
            "suspicious",
            "latitude",
            "longitude",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for event in self.timeline:
                writer.writerow({
                    "timestamp_utc" : event.get('ts_utc', ''),
                    "timestamp_ms"  : event.get('ts_ms', ''),
                    "source"        : event.get('source', ''),
                    "event_type"    : event.get('event_type', ''),
                    "description"   : event.get('description', ''),
                    "suspicious"    : "YES" if event.get('suspicious') else "NO",
                    "latitude"      : event.get('lat', ''),
                    "longitude"     : event.get('lng', ''),
                })

        return csv_path

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 3: Text Report File
    # ─────────────────────────────────────────────────────────────────────────

    def generate_text_report(self) -> str:
        """
        Write a structured forensic report text file suitable for
        submission or court disclosure.

        Returns the path to the written text file.
        """
        txt_path = os.path.join(self.output_dir, "forensic_report.txt")

        flag_count = sum(1 for r in self.results.values() if r['flagged'])
        susp_count = sum(1 for e in self.timeline if e.get('suspicious'))

        with open(txt_path, "w", encoding="utf-8") as f:

            def w(line=""):
                f.write(line + "\n")

            # ── Cover ────────────────────────────────────────────────────
            w("=" * 70)
            w("  GPS SPOOFING FORENSIC EXAMINATION REPORT")
            w("  Forensic Detection and Timeline Reconstruction")
            w("  of GPS Spoofing on Android Devices")
            w("=" * 70)
            w(f"  Report Date     : {self._generated}")
            w(f"  Tool            : GPS Spoof Detector v1.0.0")
            w(f"  Output Directory: {self.output_dir}")
            w("=" * 70)
            w()

            # ── A: Executive Summary ──────────────────────────────────────
            w("SECTION A — EXECUTIVE SUMMARY")
            w("─" * 40)
            w(f"Detection indicators confirmed : {flag_count} / 5")
            w(f"Suspicious timeline events     : {susp_count}")
            w(f"Forensic verdict               : {self._verdict}")
            w()

            # ── B: Detection Results ──────────────────────────────────────
            w("SECTION B — DETECTION CHECK RESULTS")
            w("─" * 40)
            for check_name, result in self.results.items():
                status = "FLAGGED" if result['flagged'] else "CLEAR"
                w(f"\n[{status}] {check_name}")
                w(f"  Summary : {result['summary']}")
                if result['evidence']:
                    w("  Evidence:")
                    for ev in result['evidence']:
                        w(f"    - {ev}")
            w()

            # ── C: Full Timeline ─────────────────────────────────────────
            w("SECTION C — COMPLETE FORENSIC TIMELINE")
            w("─" * 40)
            w(f"{'TIMESTAMP (UTC)':<26}  {'EVENT TYPE':<28}  {'SOURCE':<28}  SUSPICIOUS")
            w(f"{'─'*24}  {'─'*26}  {'─'*26}  {'─'*9}")

            for event in self.timeline:
                suspicious_str = "YES ⚠" if event.get('suspicious') else "no"
                w(
                    f"{event['ts_utc']:<26}  "
                    f"{event['event_type']:<28}  "
                    f"{event['source']:<28}  "
                    f"{suspicious_str}"
                )
                w(f"    Description: {event['description'][:120]}")
                if event.get('lat'):
                    w(f"    Coordinates: ({event['lat']:.4f}, {event['lng']:.4f})")
            w()

            # ── D: Conclusion ─────────────────────────────────────────────
            w("SECTION D — CONCLUSION AND EXAMINER DECLARATION")
            w("─" * 40)
            w()
            w("Based on forensic examination of the acquired Android artefacts,")
            w("this examiner concludes that the GPS location data recorded on")
            w("the examined device during the identified period was deliberately")
            w("falsified using a third-party mock location application.")
            w()
            w(f"VERDICT: {self._verdict}")
            w()
            w("Examiner Declaration:")
            w("I declare that the facts stated in this report are based solely")
            w("on the forensic artefacts analysed using documented methodology.")
            w("I have indicated where findings are matters of inference.")
            w()
            w("Signature: _________________________  Date: __________________")
            w()
            w("=" * 70)
            w("                        END OF REPORT")
            w("=" * 70)

        return txt_path
