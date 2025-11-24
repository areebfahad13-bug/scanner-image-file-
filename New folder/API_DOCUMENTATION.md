# EDR Scanner REST API Documentation

## Overview

The EDR Scanner provides a comprehensive REST API for automated malware detection and analysis. The API supports file uploads, multi-layered scanning, and real-time result retrieval.

**Base URL:** `http://localhost:8000`

**API Version:** 2.0.0

## Quick Start

### Starting the API Server

```bash
cd "New folder/api"
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Interactive Documentation

Once the server is running, visit:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Authentication

Currently, the API does not require authentication. In production, implement API key authentication:

```python
# Add to headers
headers = {
    "X-API-Key": "your-api-key"
}
```

## Endpoints

### 1. Root Endpoint

**GET** `/`

Get API information and available endpoints.

**Response:**
```json
{
    "name": "EDR Scanner API",
    "version": "2.0.0",
    "endpoints": ["/health", "/scan", "/upload", ...]
}
```

---

### 2. Health Check

**GET** `/health`

Check API and scanner health status.

**Response:**
```json
{
    "status": "healthy",
    "scanners_available": {
        "layer1": true,
        "layer2": true,
        "layer3": true,
        "dl_classifier": true,
        "behavioral": true,
        "threat_intel": true,
        "file_parser": true
    },
    "version": "2.0.0",
    "uptime": 3600.5
}
```

---

### 3. Upload File

**POST** `/upload`

Upload a file for scanning.

**Request:**
```bash
curl -X POST "http://localhost:8000/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/file.exe"
```

**Python Example:**
```python
import requests

with open('file.exe', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:8000/upload', files=files)
    print(response.json())
```

**Response:**
```json
{
    "success": true,
    "file_path": "data/uploads/uuid-filename.exe",
    "original_name": "file.exe",
    "size": 102400,
    "hash": "sha256hash...",
    "upload_time": "2025-11-25T10:30:00"
}
```

---

### 4. Submit Scan

**POST** `/scan`

Submit a file for scanning.

**Request Body:**
```json
{
    "file_path": "data/uploads/uuid-filename.exe",
    "layers": [1, 2, 3],
    "enable_behavioral": false,
    "enable_threat_intel": true,
    "enable_deep_learning": true
}
```

**Parameters:**
- `file_path` (required): Path to file (from upload response)
- `layers` (optional): List of layers to execute [1, 2, 3]
- `enable_behavioral` (optional): Enable behavioral analysis (default: false)
- `enable_threat_intel` (optional): Query threat intelligence (default: true)
- `enable_deep_learning` (optional): Use DL classifier (default: true)

**Python Example:**
```python
import requests

scan_request = {
    "file_path": "data/uploads/file.exe",
    "layers": [1, 2, 3],
    "enable_threat_intel": True
}

response = requests.post('http://localhost:8000/scan', json=scan_request)
result = response.json()
scan_id = result['scan_id']
print(f"Scan submitted: {scan_id}")
```

**Response:**
```json
{
    "scan_id": "uuid-scan-id",
    "status": "queued",
    "message": "Scan submitted successfully"
}
```

---

### 5. Get Scan Results

**GET** `/scan/{scan_id}`

Retrieve scan results by ID.

**Request:**
```bash
curl "http://localhost:8000/scan/uuid-scan-id"
```

**Python Example:**
```python
import requests
import time

scan_id = "uuid-scan-id"

# Poll for results
while True:
    response = requests.get(f'http://localhost:8000/scan/{scan_id}')
    result = response.json()
    
    if result['status'] == 'completed':
        print("Scan completed!")
        print(f"Is malicious: {result['is_malicious']}")
        print(f"Confidence: {result['confidence']}")
        break
    elif result['status'] == 'failed':
        print("Scan failed:", result.get('error'))
        break
    else:
        print(f"Status: {result['status']} ({result['progress']}%)")
        time.sleep(2)
```

**Response (In Progress):**
```json
{
    "scan_id": "uuid-scan-id",
    "status": "running",
    "progress": 45
}
```

**Response (Completed):**
```json
{
    "scan_id": "uuid-scan-id",
    "file_path": "data/uploads/file.exe",
    "file_hash": "sha256hash...",
    "timestamp": "2025-11-25T10:35:00",
    "layers_executed": [1, 2, 3],
    "is_malicious": true,
    "confidence": 0.92,
    "risk_score": 0.85,
    "details": {
        "layer1": {
            "is_threat": true,
            "confidence": 0.95,
            "details": {
                "clamav": {"detected": true, "virus_name": "Trojan.Generic"},
                "yara": {"detected": true, "matches": ["suspicious_pattern"]}
            }
        },
        "layer2": {
            "is_anomaly": true,
            "anomaly_score": 0.87
        },
        "layer3": {
            "apt_score": 0.65
        },
        "threat_intelligence": {
            "sources": {
                "virustotal": {
                    "scanned": true,
                    "positives": 45,
                    "total": 70,
                    "threat_label": "high_confidence_malicious"
                }
            },
            "aggregated": {
                "is_malicious": true,
                "confidence": 0.85,
                "threat_level": "high"
            }
        }
    }
}
```

---

### 6. Get Statistics

**GET** `/statistics`

Get overall scanner statistics.

**Response:**
```json
{
    "total_scans": 150,
    "active_scans": 2,
    "completed_scans": 145,
    "malicious_detected": 23,
    "layer1": {
        "yara_available": true,
        "yara_loaded": true,
        "clamav_available": true,
        "clamav_connected": false
    },
    "behavioral": {
        "total_analyzed": 50,
        "suspicious_count": 8,
        "suspicious_rate": 0.16
    }
}
```

---

### 7. Delete Scan

**DELETE** `/scan/{scan_id}`

Delete scan results.

**Request:**
```bash
curl -X DELETE "http://localhost:8000/scan/uuid-scan-id"
```

**Response:**
```json
{
    "success": true,
    "message": "Scan deleted"
}
```

---

### 8. Scanner Status

**GET** `/scanners/status`

Get detailed status of all scanner components.

**Response:**
```json
{
    "layer1": {
        "available": true,
        "stats": {
            "yara_available": true,
            "clamav_available": true
        }
    },
    "layer2": {
        "available": true,
        "model_loaded": true
    },
    "deep_learning": {
        "available": true,
        "info": {
            "architecture": "efficientnet",
            "num_classes": 2,
            "grad_cam_enabled": true
        }
    },
    "file_parser": {
        "available": true,
        "supported_types": [".pdf", ".docx", ".xlsx"]
    }
}
```

---

## Complete Workflow Example

```python
import requests
import time
from pathlib import Path

API_BASE = "http://localhost:8000"

def scan_file(file_path: str):
    \"\"\"Complete workflow: upload, scan, and get results.\"\"\"
    
    # 1. Upload file
    print(f"Uploading {file_path}...")
    with open(file_path, 'rb') as f:
        upload_response = requests.post(
            f"{API_BASE}/upload",
            files={'file': f}
        )
    
    upload_data = upload_response.json()
    print(f"File uploaded: {upload_data['hash']}")
    
    # 2. Submit scan
    print("Submitting scan...")
    scan_request = {
        "file_path": upload_data['file_path'],
        "layers": [1, 2, 3],
        "enable_threat_intel": True,
        "enable_behavioral": False,  # Safer to keep disabled
        "enable_deep_learning": True
    }
    
    scan_response = requests.post(
        f"{API_BASE}/scan",
        json=scan_request
    )
    
    scan_id = scan_response.json()['scan_id']
    print(f"Scan ID: {scan_id}")
    
    # 3. Poll for results
    print("Waiting for results...")
    while True:
        result_response = requests.get(f"{API_BASE}/scan/{scan_id}")
        result = result_response.json()
        
        if result['status'] == 'completed':
            break
        elif result['status'] == 'failed':
            print(f"Scan failed: {result.get('error')}")
            return None
        
        print(f"Progress: {result.get('progress', 0)}%")
        time.sleep(2)
    
    # 4. Display results
    print("\\n=== SCAN RESULTS ===")
    print(f"File: {result['file_path']}")
    print(f"Hash: {result['file_hash']}")
    print(f"Malicious: {result['is_malicious']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk Score: {result['risk_score']:.2%}")
    
    if result['is_malicious']:
        print("\\n⚠️  THREAT DETECTED!")
        
        # Show layer results
        if 'layer1' in result['details']:
            l1 = result['details']['layer1']
            if l1.get('details', {}).get('clamav', {}).get('detected'):
                print(f"  ClamAV: {l1['details']['clamav']['virus_name']}")
            if l1.get('details', {}).get('yara', {}).get('detected'):
                print(f"  YARA: {l1['details']['yara']['matches']}")
        
        # Show threat intelligence
        if 'threat_intelligence' in result['details']:
            ti = result['details']['threat_intelligence']
            agg = ti.get('aggregated', {})
            print(f"  Threat Level: {agg.get('threat_level', 'unknown').upper()}")
    else:
        print("\\n✓ File appears clean")
    
    return result

# Example usage
if __name__ == "__main__":
    result = scan_file("test_file.exe")
```

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Successful request
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Invalid request parameters
- `500 Internal Server Error`: Server error

### Error Response Format

```json
{
    "detail": "Error message describing the issue"
}
```

---

## Rate Limiting

Currently, no rate limiting is implemented. For production:

- Implement rate limiting middleware
- Limit: 100 requests per minute per IP
- Burst: 20 requests

---

## Best Practices

### 1. Asynchronous Scanning

Don't wait for scan completion in the same request:

```python
# Bad: Synchronous
response = requests.post('/scan', json=request)
# ... blocks until complete

# Good: Asynchronous
scan_response = requests.post('/scan', json=request)
scan_id = scan_response.json()['scan_id']

# Check later
result = requests.get(f'/scan/{scan_id}')
```

### 2. Cleanup Old Scans

Periodically delete old scan results:

```python
for scan_id in old_scan_ids:
    requests.delete(f'/scan/{scan_id}')
```

### 3. Handle Timeouts

```python
import requests
from requests.exceptions import Timeout

try:
    response = requests.post('/scan', json=data, timeout=30)
except Timeout:
    print("Request timed out")
```

### 4. Verify SSL (Production)

```python
# Development
response = requests.get(url, verify=False)

# Production
response = requests.get(url, verify=True)
```

---

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t edr-scanner-api .
docker run -p 8000:8000 edr-scanner-api
```

### Production Configuration

```python
# config.py
import os

class Config:
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", 8000))
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
    ENABLE_CORS = os.getenv("ENABLE_CORS", "true").lower() == "true"
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
```

---

## Troubleshooting

### Issue: "Scanner not initialized"

**Solution:** Ensure all required files and models are in place:

```bash
# Check directory structure
ls -R data/ models/
```

### Issue: "File upload failed"

**Solution:** Check upload directory permissions:

```bash
mkdir -p data/uploads
chmod 755 data/uploads
```

### Issue: "Scan stuck in 'queued' status"

**Solution:** Check background task execution and logs:

```bash
# Check logs
tail -f logs/api.log
```

---

## Support

For issues or questions:
- GitHub Issues: [Create an issue](https://github.com/areebfahad13-bug/scanner-image-file-/issues)
- Documentation: See README.md and CONTRIBUTING.md

---

**API Version:** 2.0.0  
**Last Updated:** 2025-11-25
