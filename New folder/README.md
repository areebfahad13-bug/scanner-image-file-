# EDR System - Three-Layered Triage Architecture

![EDR Architecture](https://img.shields.io/badge/Architecture-Three--Layered-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Overview

Advanced Endpoint Detection and Response (EDR) system with a **Three-Layered Triage Architecture** designed for efficient threat detection and behavioral anomaly analysis.

### Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    EDR System                           │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Signature Filter                             │
│  ├─ ClamAV (Antivirus)                                 │
│  └─ Compiled YARA Rules (High-speed pattern matching)  │
│                                                         │
│  Layer 2: APSA ML Core                                 │
│  ├─ IsolationForest (Behavioral Anomaly Detection)     │
│  ├─ Feature Extraction (Entropy, Fuzzy Hashing)        │
│  └─ Dynamic Signature Generation (K-Means/DBSCAN)      │
│                                                         │
│  Layer 3: APT Correlation                              │
│  ├─ SQLite Event Store (Long-term tracking)            │
│  ├─ Threat Intelligence API (VirusTotal/MISP)          │
│  └─ Multi-dimensional Risk Scoring                     │
└─────────────────────────────────────────────────────────┘
```

## ✨ Key Features

### 🛡️ Security Features
- **Multi-layered Detection**: Sequential filtering from fast signature matching to sophisticated ML analysis
- **Behavioral Anomaly Detection**: Unsupervised learning with IsolationForest
- **Dynamic Signature Generation**: Automatic YARA rule creation from clustered anomalies
- **APT Correlation**: Long-term threat tracking and pattern recognition
- **Secure File I/O**: TOCTOU prevention, thread-safe operations
- **Least Privilege Remediation**: Isolated subprocess execution for quarantine/delete operations

### 📊 Dashboard Features
- **Bento Grid Layout**: Modern, organized UI for quick content scanning
- **Central Risk Score**: Large, color-coded threat likelihood display (0-100%)
- **Layered Visualization**: Bar chart breakdown of scores from each detection layer
- **Performance Metrics**: Real-time scan latency and throughput monitoring
- **System Activity Log**: Asynchronous file status logging
- **Quarantine Management**: Review and manage quarantined files

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- Windows 10/11 (Linux/macOS compatible with minor modifications)
- 4GB RAM minimum (8GB recommended)
- ClamAV (optional but recommended)

### ClamAV Installation (Windows)
1. Download ClamAV from [https://www.clamav.net/downloads](https://www.clamav.net/downloads)
2. Install and start the ClamAV daemon
3. Update virus definitions: `freshclam`

## 🔧 Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/edr-system.git
cd edr-system
```

### 2. Create Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Install YARA Rules
Place your `.yar` or `.yara` rule files in `data/yara_rules/`:
```
data/
  yara_rules/
    malware_rules.yar
    suspicious_patterns.yar
```

## 🚀 Usage

### Quick Start
```powershell
cd app
python main_window.py
```

### Training ML Model (Optional)
Before first use, train the anomaly detection model on benign files:

```python
from app.layer2_apsa import Layer2APSA

# Initialize Layer 2
layer2 = Layer2APSA()

# Collect benign file paths
benign_files = [
    'path/to/benign/file1.exe',
    'path/to/benign/file2.dll',
    # ... more benign samples
]

# Train model
layer2.train_model(benign_files)

# Save model
layer2.save_model('data/ml_model.pkl')
```

### Scanning Workflow

1. **Launch Application**: Run `main_window.py`
2. **Select Directory**: Click "Select Directory to Scan"
3. **Monitor Progress**: Watch real-time scan progress in dashboard
4. **Review Results**: Examine threat scores and layer breakdowns
5. **Take Action**: Quarantine or delete detected threats

## 📁 Project Structure

```
EDR_System/
├── app/
│   ├── main_window.py              # PyQt5 GUI with Bento Grid Layout
│   ├── security_io.py              # Secure file I/O, path validation
│   ├── remediation_helper.py       # Least privilege remediation
│   ├── ml_core.py                  # IsolationForest ML model
│   ├── layer1_scanner.py           # ClamAV + YARA signature filter
│   ├── layer2_apsa.py              # Behavioral anomaly detection
│   └── layer3_apt.py               # APT correlation engine
├── data/
│   ├── yara_rules/                 # YARA rule files (.yar)
│   ├── quarantine/                 # Quarantined files
│   ├── events_db.sqlite            # Event/findings database
│   └── benign_baseline.csv         # ML training data (optional)
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## 🧪 Detection Methodology

### Layer 1: Signature Filter (Target: <500ms)
- **ClamAV**: Matches against 8.5M+ virus signatures
- **YARA**: Custom behavioral rules (compiled for speed)
- **Output**: `(is_known_threat, confidence_score)`

### Layer 2: APSA (Adaptive Pattern Scoring & Analysis)
**Feature Extraction:**
- File entropy (Shannon entropy)
- Byte frequency distribution
- Fuzzy hashing (ssdeep)
- File metadata (size, extension, timestamps)

**ML Detection:**
- IsolationForest with contamination=0.1
- Anomaly score: 0.0 (benign) to 1.0 (highly anomalous)
- Threshold: 0.6 for flagging

**Dynamic Signatures:**
- Clusters anomalies using DBSCAN
- Generates behavioral YARA rules
- Feeds back to Layer 1

### Layer 3: APT Correlation
**Event Tracking:**
- SQLite database for persistent storage
- Tracks: file scans, detections, indicators
- Time-series analysis for pattern recognition

**Risk Scoring:**
```python
final_score = (
    layer1_confidence * 0.30 +    # Signature match
    layer2_anomaly * 0.35 +       # Behavioral analysis
    apt_correlation * 0.20 +      # Historical patterns
    threat_intel * 0.15           # VirusTotal/MISP
)
```

## 🔐 Security Features

### Secure File I/O (`security_io.py`)
- **Path Validation**: `Path.resolve(strict=True)` prevents TOCTOU
- **Thread Safety**: Global `threading.Lock()` for shared resources
- **Chunked Reading**: 1MB buffers for memory efficiency

### Remediation (`remediation_helper.py`)
- **Subprocess Isolation**: Separate process for privileged operations
- **Argument Validation**: Rigid whitelist prevents shell injection
- **Secure Delete**: 3-pass overwrite before removal
- **Quarantine Metadata**: JSON tracking with SHA256 hashes

## 📈 Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| Layer 1 Latency | <500ms | 100-300ms |
| Layer 2 Latency | <2s | 500ms-1.5s |
| Layer 3 Latency | <300ms | 50-200ms |
| Total Scan Time | <2.3s | 1-2s |
| Throughput | >10 MB/s | 15-30 MB/s |

## 🛠️ Configuration

### VirusTotal API (Optional)
Add your API key to enable threat intelligence:

```python
# In main_window.py or layer3_apt.py
layer3 = Layer3APT(
    db_path='data/events_db.sqlite',
    virustotal_api_key='YOUR_API_KEY_HERE'
)
```

Get a free API key: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)

## 🐛 Troubleshooting

### ClamAV Not Detected
```powershell
# Check if ClamAV daemon is running
Get-Service -Name "*clam*"

# Start ClamAV daemon
Start-Service -Name "ClamAV"
```

### YARA Rules Not Loading
- Ensure `.yar` files are in `data/yara_rules/`
- Check rule syntax: `yara -c rule_file.yar`
- Review logs for compilation errors

### ML Model Not Trained
- Train on benign samples (see Usage section)
- System falls back to heuristic analysis if model unavailable

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- **YARA Project**: Pattern matching engine
- **ClamAV**: Open-source antivirus engine
- **scikit-learn**: Machine learning library
- **VirusTotal**: Threat intelligence API

---

**Built with ❤️ for the security community**
