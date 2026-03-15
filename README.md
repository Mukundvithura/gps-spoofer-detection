# GPS Spoofing Forensic Detection Tool
### Academic Cyber Forensics Project
**Forensic Detection and Timeline Reconstruction of GPS Spoofing on Android Devices**

---

## Overview

A modular Python-based forensic tool that:
1. Acquires Android artefacts via ADB (or reads from an offline dump)
2. Parses forensic artefacts across six artefact categories
3. Runs five independent spoofing detection checks
4. Reconstructs a unified forensic timeline
5. Generates a console report, CSV timeline, and text forensic report

---

## Project Structure

```
gps_spoof_detector/
├── main.py          # Entry point — CLI argument parser and orchestrator
├── adb_acquire.py   # ADB acquisition module + demo artefact generator
├── parsers.py       # Artefact parser (XML, SQLite, logcat, packages)
├── detector.py      # Spoofing detection engine (5 independent checks)
├── timeline.py      # Timeline reconstruction engine
├── report.py        # Console, CSV, and text report generator
└── README.md        # This file
```

---

## Requirements

- Python 3.8+
- Standard library only (`sqlite3`, `subprocess`, `os`, `csv`, `argparse`, `datetime`, `math`, `re`, `hashlib`, `xml.etree.ElementTree`)
- ADB (Android Debug Bridge) installed and in PATH — for live mode only
- pandas (optional — not required for core functionality)

Install ADB:
```bash
# Ubuntu / Debian
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools

# Windows — download Android SDK Platform Tools from developer.android.com
```

---

## Usage

### Mode 1: Demo (No device required — for testing and viva)
```bash
python main.py --mode demo --output ./demo_output
```

### Mode 2: Live ADB Device
```bash
# Enable USB Debugging on device: Settings > Developer Options > USB Debugging
python main.py --mode live --output ./case_001
```

### Mode 3: Offline Filesystem Dump
```bash
python main.py --mode offline --dump-path ./extracted_fs --output ./case_001
```

### Options
```
--mode              live | offline | demo
--dump-path PATH    Path to extracted filesystem (offline mode)
--output DIR        Output directory for all forensic files
--device-serial SN  ADB serial if multiple devices connected
--speed-threshold N Impossible travel speed threshold in km/h (default: 900)
--verbose           Enable debug output
```

---

## Detection Checks

| # | Check | Method |
|---|-------|--------|
| 1 | Mock Location Setting | Parse settings_secure.xml for Developer Options + mock app designation |
| 2 | Spoofing App Installed | Match package list against 10 known spoofing app package names |
| 3 | Impossible Travel Speed | Haversine distance / time delta > 900 km/h between consecutive GPS fixes |
| 4 | Cell Tower Contradiction | GPS location inconsistent with simultaneously active cell tower region |
| 5 | Logcat Mock Events | System logs containing MockLocationProvider / setTestProviderLocation |

---

## Output Files

```
<output_dir>/
├── acquisition/                    # Pulled artefacts (live/demo mode)
│   ├── data/system/users/0/       # Settings XML files
│   ├── data/data/com.google.*/    # GMS databases
│   ├── logcat_dump.txt
│   ├── package_list.txt
│   └── CHAIN_OF_CUSTODY_HASHES.txt
├── forensic_timeline.csv           # Complete event timeline (importable)
└── forensic_report.txt             # Court-structured forensic report
```
