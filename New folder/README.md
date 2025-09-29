# Python Desktop Antivirus Scanner App

## Features
- Select directories to scan
- Scan files for viruses/malware using ClamAV or YARA
- Quarantine or delete detected threats
- Display detailed scan report

## Architecture
- GUI: PyQt5 (can be swapped for Tkinter)
- Scanning Engine: ClamAV or YARA integration
- Quarantine: Moves threats to a secure folder
- Reporting: Generates detailed scan reports

## Security & Performance Considerations
- Use secure file I/O (avoid race conditions, validate paths)
- Run scans with least privilege
- Use efficient file reading (buffered I/O)
- Use compiled YARA rules for speed
- Avoid scanning system/OS files unless necessary

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Run: `python scanner_app/main.py`
