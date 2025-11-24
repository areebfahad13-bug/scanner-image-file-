# EDR System - Quick Reference Card

## 🚀 Quick Start

### Installation (One-Time Setup)
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application
python run_edr.py
```

### Daily Usage
```powershell
# Launch EDR System
python run_edr.py

# Or directly launch GUI
cd app
python main_window.py
```

## 📁 Project Structure
```
New folder/
├── app/                     ← Core EDR modules
│   ├── main_window.py       ← GUI application
│   ├── layer1_scanner.py    ← Signature detection
│   ├── layer2_apsa.py       ← ML anomaly detection
│   ├── layer3_apt.py        ← APT correlation
│   ├── ml_core.py           ← ML engine
│   ├── security_io.py       ← Secure file I/O
│   └── remediation_helper.py ← Quarantine/delete
│
├── data/                    ← Data and storage
│   ├── yara_rules/          ← Add .yar files here
│   ├── quarantine/          ← Quarantined files
│   └── events_db.sqlite     ← Auto-created database
│
├── run_edr.py              ← Launch script
├── train_model.py          ← ML training script
├── requirements.txt        ← Dependencies
└── README.md               ← Full documentation
```

## ⚙️ Configuration

### Add YARA Rules
1. Create `.yar` or `.yara` file
2. Place in `data/yara_rules/`
3. Restart application (auto-loads)

### Train ML Model (Optional)
```powershell
# Train on benign files
python train_model.py C:\Path\To\Benign\Files

# Save to specific location
python train_model.py C:\Benign --output data\my_model.pkl
```

### Enable VirusTotal API
Edit `app/main_window.py`, line ~38:
```python
self.layer3 = Layer3APT(
    db_path=str(self.db_path),
    virustotal_api_key='YOUR_API_KEY'  # Add your key here
)
```

## 🎯 GUI Overview

### Dashboard Layout
```
┌─────────────────────────────────────────────┐
│  [Select Directory]  [Stop Scan]            │
├───────────────┬───────────────┬─────────────┤
│               │               │             │
│  RISK SCORE   │  LAYER SCORES │ PERFORMANCE │
│   96.3%       │  L1: ███      │ Latency: 2s │
│   🔴 THREAT   │  L2: ███      │ Files: 250  │
│               │  L3: ███      │             │
├───────────────┴───────────────┴─────────────┤
│  SYSTEM ACTIVITY LOG                        │
│  ✓ Scanning file1.exe...                    │
│  🔴 THREAT: malware.exe (Score: 95%)        │
│  ✓ Quarantined: malware.exe                 │
└─────────────────────────────────────────────┘
```

### Tabs
- **Dashboard**: Main scanning interface
- **Quarantine Management**: Review quarantined files

## 🔍 Detection Layers

### Layer 1: Signature Filter
- **Speed**: <500ms
- **Engine**: ClamAV + YARA
- **Output**: Known threat (yes/no)

### Layer 2: Behavioral Analysis
- **Speed**: 0.5-1.5s
- **Engine**: IsolationForest ML
- **Features**: Entropy, byte patterns, file metadata
- **Output**: Anomaly score (0.0-1.0)

### Layer 3: APT Correlation
- **Speed**: 50-200ms
- **Engine**: SQLite + VirusTotal
- **Analysis**: Historical patterns, threat intel
- **Output**: Final composite score

## 📊 Score Interpretation

| Score | Status | Color | Action |
|-------|--------|-------|--------|
| 0-30% | CLEAN | 🟢 Green | None |
| 30-60% | SUSPICIOUS | 🟡 Orange | Review |
| 60-100% | THREAT | 🔴 Red | Quarantine |

## 🛡️ Remediation Actions

### Quarantine
- Moves file to `data/quarantine/`
- Saves metadata (hash, date, threat info)
- File can be restored later

### Delete
- 3-pass secure overwrite
- Permanent removal
- Cannot be recovered

### Restore
- Returns file to original location
- Removes quarantine metadata
- Use with caution

## 🔧 Troubleshooting

### "YARA not available"
```powershell
pip install yara-python
```

### "ClamAV not available"
- Optional: Download from https://www.clamav.net/downloads
- Or continue without (uses YARA only)

### "ssdeep installation failed"
```powershell
# Option 1: Install Visual C++ Build Tools
# Option 2: Skip (system uses fallback hashing)
pip install ssdeep --no-cache-dir
```

### GUI doesn't launch
```powershell
# Check PyQt5
pip install PyQt5 --upgrade

# Run with error output
python run_edr.py 2>&1 | Out-File error.log
```

### Slow scanning
- Large files (>1GB) are skipped in Layer 2
- Many files: Expect 1-2s per file
- Close other applications for better performance

## 📈 Performance Tips

### Optimize Scanning
1. **Exclude large media files**: Skip .mp4, .mkv, etc.
2. **Use compiled YARA rules**: Faster loading
3. **Train ML model**: Better accuracy, faster decisions
4. **Enable ClamAV**: Parallel detection

### System Requirements
- **Minimum**: 4GB RAM, Dual-core CPU
- **Recommended**: 8GB RAM, Quad-core CPU
- **Storage**: 500MB for app + database

## 🔐 Security Best Practices

### Before Scanning
1. ✅ Close sensitive applications
2. ✅ Backup important files
3. ✅ Run with standard user (not admin)

### After Detection
1. ✅ Review threat details
2. ✅ Verify false positives
3. ✅ Quarantine (don't delete immediately)
4. ✅ Update YARA rules regularly

### Regular Maintenance
- Update virus definitions (ClamAV)
- Retrain ML model quarterly
- Review quarantine weekly
- Clean old database entries

## 📞 Support & Resources

### Documentation
- **Full Guide**: See README.md
- **Implementation**: See IMPLEMENTATION_SUMMARY.md
- **Code Examples**: See app/\*.py files

### Common Commands
```powershell
# Check dependencies
pip list | Select-String "PyQt5|scikit|yara"

# View logs (when running)
# Check terminal output

# Database location
.\data\events_db.sqlite

# Quarantine location
.\data\quarantine\
```

## 🎓 Learning Resources

### Understanding the Layers
1. **Layer 1**: Pattern matching (fast, specific)
2. **Layer 2**: Behavior analysis (ML, generalized)
3. **Layer 3**: Context + history (APT detection)

### Key Concepts
- **Entropy**: Randomness measure (high = packed/encrypted)
- **Fuzzy Hashing**: Similarity detection (ssdeep)
- **IsolationForest**: Outlier detection algorithm
- **YARA**: Pattern matching language
- **APT**: Advanced Persistent Threat

## ⚡ Keyboard Shortcuts

- `Ctrl+O`: Select directory (when focused)
- `Ctrl+Q`: Quit application
- `Ctrl+C`: Stop scan (in terminal)

## 🆘 Emergency Actions

### Stop Runaway Scan
1. Click "Stop Scan" button
2. Or press Ctrl+C in terminal
3. Or close application window

### Restore Quarantined File
1. Go to "Quarantine Management" tab
2. Select file
3. Click "Restore Selected"

### Clear All Data
```powershell
# Remove database
Remove-Item data\events_db.sqlite

# Remove quarantine
Remove-Item data\quarantine\* -Recurse

# App recreates automatically on next run
```

---

**Quick Help**: For detailed information, see README.md
**Emergency**: Close application and contact security team
