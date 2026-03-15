#!/usr/bin/env python3
"""
=============================================================================
GPS Spoofing Forensic Detection Tool
Project: Forensic Detection and Timeline Reconstruction of GPS Spoofing
         on Android Devices
Author : Cybersecurity / Digital Forensics Academic Project
Version: 1.0.0
=============================================================================

Entry point. Parses CLI arguments, orchestrates acquisition, parsing,
detection, timeline reconstruction, and report generation.

Usage:
    # Live device (ADB connected):
    python main.py --mode live --output ./case_output

    # Offline extracted filesystem dump:
    python main.py --mode offline --dump-path ./fs_dump --output ./case_output

    # Demo mode (generates synthetic artefacts for testing):
    python main.py --mode demo --output ./case_output
"""

import argparse
import os
import sys
import datetime

# Import project modules
from adb_acquire  import ADBClient
from parsers      import ArtifactParser
from detector     import SpoofingDetector
from timeline     import TimelineEngine
from report       import ReportGenerator


# ─────────────────────────────────────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    """Define and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="gps_spoof_detector",
        description=(
            "GPS Spoofing Forensic Detection Tool — "
            "Detects and reconstructs GPS spoofing artefacts on Android devices."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode live --output ./case_001
  python main.py --mode offline --dump-path ./fs_dump --output ./case_001
  python main.py --mode demo --output ./demo_output
        """
    )

    parser.add_argument(
        "--mode",
        choices=["live", "offline", "demo"],
        required=True,
        help=(
            "Acquisition mode: "
            "'live' = ADB-connected device, "
            "'offline' = extracted filesystem dump, "
            "'demo' = synthetic test data."
        )
    )

    parser.add_argument(
        "--dump-path",
        type=str,
        default=None,
        help="Path to extracted filesystem dump directory (required for --mode offline)."
    )

    parser.add_argument(
        "--output",
        type=str,
        default="./forensic_output",
        help="Directory for all forensic output files (default: ./forensic_output)."
    )

    parser.add_argument(
        "--device-serial",
        type=str,
        default=None,
        help="Specific ADB device serial number (optional; used if multiple devices connected)."
    )

    parser.add_argument(
        "--speed-threshold",
        type=float,
        default=900.0,
        help=(
            "Impossible travel speed threshold in km/h. "
            "Consecutive GPS fixes implying speed above this value are flagged as spoofed. "
            "Default: 900 km/h (speed of sound)."
        )
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug output."
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser     = build_arg_parser()
    args       = parser.parse_args()

    # ── Banner ────────────────────────────────────────────────────────────────
    print("=" * 70)
    print("  GPS SPOOFING FORENSIC DETECTION TOOL  v1.0.0")
    print("  Academic Cyber Forensics Project")
    print("=" * 70)
    print(f"  Mode         : {args.mode.upper()}")
    print(f"  Output Dir   : {args.output}")
    print(f"  Speed Limit  : {args.speed_threshold} km/h")
    print(f"  Started      : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 70)

    # ── Output directory ──────────────────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)
    acquisition_dir = os.path.join(args.output, "acquisition")
    os.makedirs(acquisition_dir, exist_ok=True)

    # ── STEP 1: Acquisition ───────────────────────────────────────────────────
    print("\n[STEP 1/5] ACQUISITION")
    print("-" * 40)

    adb_client = ADBClient(
        serial=args.device_serial,
        output_dir=acquisition_dir,
        verbose=args.verbose
    )

    if args.mode == "live":
        # Real ADB pull from connected device
        success = adb_client.acquire_all()
        if not success:
            print("[FATAL] Acquisition failed. Check ADB connection and try again.")
            sys.exit(1)
        artefact_root = acquisition_dir

    elif args.mode == "offline":
        # Use pre-extracted filesystem dump
        if not args.dump_path or not os.path.isdir(args.dump_path):
            print("[FATAL] --dump-path must point to a valid directory in offline mode.")
            sys.exit(1)
        artefact_root = args.dump_path
        print(f"  [INFO] Using offline dump: {artefact_root}")

    elif args.mode == "demo":
        # Generate synthetic artefacts for demonstration / viva
        print("  [INFO] Generating synthetic forensic artefacts for demo mode...")
        adb_client.generate_demo_artefacts()
        artefact_root = acquisition_dir
        print("  [OK]   Demo artefacts created.")

    # ── STEP 2: Parse Artefacts ───────────────────────────────────────────────
    print("\n[STEP 2/5] ARTEFACT PARSING")
    print("-" * 40)

    artifact_parser = ArtifactParser(
        artefact_root=artefact_root,
        verbose=args.verbose
    )
    parsed_data = artifact_parser.parse_all()

    print(f"  [OK] Mock Location Setting   : {parsed_data.get('mock_location_enabled', 'N/A')}")
    print(f"  [OK] Spoofing Apps Found     : {len(parsed_data.get('spoofing_apps', []))}")
    print(f"  [OK] GPS Location Records    : {len(parsed_data.get('gps_records', []))}")
    print(f"  [OK] Cell Tower Records      : {len(parsed_data.get('cell_records', []))}")
    print(f"  [OK] WiFi Scan Records       : {len(parsed_data.get('wifi_records', []))}")
    print(f"  [OK] App Usage Events        : {len(parsed_data.get('app_usage', []))}")

    # ── STEP 3: Spoofing Detection ────────────────────────────────────────────
    print("\n[STEP 3/5] SPOOFING DETECTION")
    print("-" * 40)

    detector = SpoofingDetector(
        parsed_data=parsed_data,
        speed_threshold_kmh=args.speed_threshold,
        verbose=args.verbose
    )
    detection_results = detector.run_all_checks()

    for check_name, result in detection_results.items():
        status = "⚠ FLAGGED" if result["flagged"] else "✓ CLEAR"
        print(f"  [{status}] {check_name}: {result['summary']}")

    # ── STEP 4: Timeline Reconstruction ──────────────────────────────────────
    print("\n[STEP 4/5] TIMELINE RECONSTRUCTION")
    print("-" * 40)

    timeline_engine = TimelineEngine(
        parsed_data=parsed_data,
        detection_results=detection_results,
        verbose=args.verbose
    )
    timeline = timeline_engine.build_timeline()

    print(f"  [OK] Timeline events merged  : {len(timeline)}")
    suspicious_count = sum(1 for e in timeline if e.get("suspicious"))
    print(f"  [OK] Suspicious events       : {suspicious_count}")

    # ── STEP 5: Report Generation ─────────────────────────────────────────────
    print("\n[STEP 5/5] REPORT GENERATION")
    print("-" * 40)

    reporter = ReportGenerator(
        parsed_data=parsed_data,
        detection_results=detection_results,
        timeline=timeline,
        output_dir=args.output,
        verbose=args.verbose
    )
    reporter.generate_console_report()
    csv_path = reporter.generate_csv_timeline()
    txt_path = reporter.generate_text_report()

    print(f"  [OK] CSV timeline saved      : {csv_path}")
    print(f"  [OK] Text report saved       : {txt_path}")

    # ── Final Verdict ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    verdict = reporter.get_verdict()
    print(f"  FORENSIC VERDICT: {verdict}")
    print("=" * 70)
    print(f"  All output saved to: {args.output}")
    print("=" * 70 + "\n")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
