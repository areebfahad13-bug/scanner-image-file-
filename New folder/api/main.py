"""
FastAPI REST API for EDR Scanner
Provides endpoints for file upload, scanning, and result retrieval.
"""
import os
import sys
import asyncio
import logging
import hashlib
import time
import json
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime
import uuid

try:
    from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from layer1_scanner import Layer1Scanner
from layer2_apsa import Layer2APSA
from layer3_apt import Layer3APT
from dl_image_classifier import ImageMalwareClassifier
from behavioral_analysis import BehavioralAnalyzer
from threat_intelligence import ThreatIntelligence
from file_parser import ExtendedFileParser

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="EDR Scanner API",
    description="Advanced malware detection with multi-layered scanning",
    version="2.0.0"
) if FASTAPI_AVAILABLE else None

# CORS configuration
if FASTAPI_AVAILABLE:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Global scanner instances
scanners = {
    'layer1': None,
    'layer2': None,
    'layer3': None,
    'dl_classifier': None,
    'behavioral': None,
    'threat_intel': None,
    'file_parser': None
}

# Scan results cache
scan_results = {}
scan_status = {}


# Pydantic models
if FASTAPI_AVAILABLE:
    class ScanRequest(BaseModel):
        file_path: str = Field(..., description="Path to file to scan")
        layers: List[int] = Field(default=[1, 2, 3], description="Layers to execute")
        enable_behavioral: bool = Field(default=False, description="Enable behavioral analysis")
        enable_threat_intel: bool = Field(default=True, description="Query threat intelligence")
        enable_deep_learning: bool = Field(default=True, description="Use deep learning classifier")
    
    class ScanResult(BaseModel):
        scan_id: str
        file_path: str
        status: str
        timestamp: str
        layers_executed: List[int]
        is_malicious: bool
        confidence: float
        risk_score: float
        details: Dict
    
    class HealthResponse(BaseModel):
        status: str
        scanners_available: Dict[str, bool]
        version: str
        uptime: float


def initialize_scanners():
    """Initialize all scanner components."""
    global scanners
    
    try:
        # Layer 1: Signature-based
        scanners['layer1'] = Layer1Scanner(yara_rules_dir='data/yara_rules')
        
        # Layer 2: ML-based APSA
        ml_model_path = 'models/ml_model.pkl'
        scanners['layer2'] = Layer2APSA(
            ml_model_path=ml_model_path if os.path.exists(ml_model_path) else None
        )
        
        # Layer 3: APT correlation
        scanners['layer3'] = Layer3APT(db_path='data/edr_events.db')
        
        # Deep learning classifier
        dl_model_path = 'models/image_classifier.h5'
        scanners['dl_classifier'] = ImageMalwareClassifier(
            model_path=dl_model_path if os.path.exists(dl_model_path) else None
        )
        
        # Behavioral analyzer
        scanners['behavioral'] = BehavioralAnalyzer(sandbox_dir='data/sandbox')
        
        # Threat intelligence
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        ha_api_key = os.getenv('HYBRID_ANALYSIS_API_KEY')
        scanners['threat_intel'] = ThreatIntelligence(
            db_path='data/threat_intel.db',
            vt_api_key=vt_api_key,
            ha_api_key=ha_api_key
        )
        
        # File parser
        scanners['file_parser'] = ExtendedFileParser()
        
        logger.info("All scanners initialized successfully")
    
    except Exception as e:
        logger.error(f"Scanner initialization failed: {e}")


# Startup event
if FASTAPI_AVAILABLE:
    @app.on_event("startup")
    async def startup_event():
        """Initialize scanners on startup."""
        initialize_scanners()


# API Endpoints

if FASTAPI_AVAILABLE:
    @app.get("/", response_model=Dict)
    async def root():
        """API root endpoint."""
        return {
            "name": "EDR Scanner API",
            "version": "2.0.0",
            "endpoints": [
                "/health",
                "/scan",
                "/scan/{scan_id}",
                "/upload",
                "/statistics"
            ]
        }
    
    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        """Check API and scanner health."""
        return {
            "status": "healthy",
            "scanners_available": {
                name: scanner is not None 
                for name, scanner in scanners.items()
            },
            "version": "2.0.0",
            "uptime": time.time()  # Should track actual uptime
        }
    
    @app.post("/upload")
    async def upload_file(file: UploadFile = File(...)):
        """
        Upload a file for scanning.
        
        Returns:
            Dictionary with file information and upload path
        """
        try:
            # Create uploads directory
            upload_dir = Path("data/uploads")
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate unique filename
            file_ext = Path(file.filename).suffix
            unique_name = f"{uuid.uuid4()}{file_ext}"
            file_path = upload_dir / unique_name
            
            # Save file
            content = await file.read()
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            return {
                "success": True,
                "file_path": str(file_path),
                "original_name": file.filename,
                "size": len(content),
                "hash": file_hash,
                "upload_time": datetime.now().isoformat()
            }
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    
    @app.post("/scan")
    async def scan_file(
        request: ScanRequest,
        background_tasks: BackgroundTasks
    ):
        """
        Submit a file for scanning.
        
        Returns:
            Scan ID for tracking progress
        """
        # Validate file exists
        if not os.path.exists(request.file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        scan_status[scan_id] = {
            "status": "queued",
            "progress": 0,
            "started_at": datetime.now().isoformat()
        }
        
        # Add scan to background tasks
        background_tasks.add_task(
            perform_scan,
            scan_id,
            request.file_path,
            request.layers,
            request.enable_behavioral,
            request.enable_threat_intel,
            request.enable_deep_learning
        )
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan submitted successfully"
        }
    
    @app.get("/scan/{scan_id}")
    async def get_scan_result(scan_id: str):
        """
        Get scan results by ID.
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            Scan results or status
        """
        # Check if scan exists
        if scan_id not in scan_status:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Return status if not complete
        if scan_status[scan_id]["status"] != "completed":
            return {
                "scan_id": scan_id,
                "status": scan_status[scan_id]["status"],
                "progress": scan_status[scan_id]["progress"]
            }
        
        # Return full results
        if scan_id in scan_results:
            return scan_results[scan_id]
        
        raise HTTPException(status_code=500, detail="Results not available")
    
    @app.get("/statistics")
    async def get_statistics():
        """
        Get scanner statistics.
        
        Returns:
            Statistics from all scanner components
        """
        stats = {
            "total_scans": len(scan_results),
            "active_scans": sum(
                1 for s in scan_status.values() 
                if s["status"] in ["queued", "running"]
            ),
            "completed_scans": sum(
                1 for s in scan_status.values() 
                if s["status"] == "completed"
            ),
            "malicious_detected": sum(
                1 for r in scan_results.values() 
                if r.get("is_malicious", False)
            )
        }
        
        # Add scanner-specific stats
        if scanners['layer1']:
            stats['layer1'] = scanners['layer1'].get_statistics()
        
        if scanners['behavioral']:
            stats['behavioral'] = scanners['behavioral'].get_statistics()
        
        return stats
    
    @app.delete("/scan/{scan_id}")
    async def delete_scan(scan_id: str):
        """Delete scan results."""
        if scan_id in scan_results:
            del scan_results[scan_id]
        if scan_id in scan_status:
            del scan_status[scan_id]
        
        return {"success": True, "message": "Scan deleted"}
    
    @app.get("/scanners/status")
    async def get_scanner_status():
        """Get status of all scanner components."""
        return {
            "layer1": {
                "available": scanners['layer1'] is not None,
                "stats": scanners['layer1'].get_statistics() if scanners['layer1'] else {}
            },
            "layer2": {
                "available": scanners['layer2'] is not None,
                "model_loaded": scanners['layer2'].ml_core.model is not None if scanners['layer2'] else False
            },
            "layer3": {
                "available": scanners['layer3'] is not None
            },
            "deep_learning": {
                "available": scanners['dl_classifier'] is not None,
                "info": scanners['dl_classifier'].get_model_info() if scanners['dl_classifier'] else {}
            },
            "behavioral": {
                "available": scanners['behavioral'] is not None
            },
            "threat_intel": {
                "available": scanners['threat_intel'] is not None
            },
            "file_parser": {
                "available": scanners['file_parser'] is not None,
                "supported_types": scanners['file_parser'].get_supported_types() if scanners['file_parser'] else []
            }
        }


async def perform_scan(
    scan_id: str,
    file_path: str,
    layers: List[int],
    enable_behavioral: bool,
    enable_threat_intel: bool,
    enable_deep_learning: bool
):
    """
    Perform comprehensive file scan.
    
    Args:
        scan_id: Scan identifier
        file_path: Path to file
        layers: Layers to execute
        enable_behavioral: Enable behavioral analysis
        enable_threat_intel: Enable threat intelligence
        enable_deep_learning: Enable deep learning
    """
    try:
        scan_status[scan_id]["status"] = "running"
        scan_status[scan_id]["progress"] = 10
        
        result = {
            "scan_id": scan_id,
            "file_path": file_path,
            "timestamp": datetime.now().isoformat(),
            "layers_executed": layers,
            "is_malicious": False,
            "confidence": 0.0,
            "risk_score": 0.0,
            "details": {}
        }
        
        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        result["file_hash"] = file_hash
        
        scan_status[scan_id]["progress"] = 20
        
        # Layer 1: Signature-based
        if 1 in layers and scanners['layer1']:
            is_threat, conf, details = scanners['layer1'].scan_file(file_path)
            result["details"]["layer1"] = {
                "is_threat": is_threat,
                "confidence": conf,
                "details": details
            }
            if is_threat:
                result["is_malicious"] = True
                result["confidence"] = max(result["confidence"], conf)
        
        scan_status[scan_id]["progress"] = 40
        
        # Layer 2: ML-based APSA
        if 2 in layers and scanners['layer2']:
            l2_result = scanners['layer2'].analyze_file(file_path)
            result["details"]["layer2"] = l2_result
            if l2_result.get("is_anomaly", False):
                result["is_malicious"] = True
                result["confidence"] = max(result["confidence"], l2_result.get("anomaly_score", 0))
        
        scan_status[scan_id]["progress"] = 60
        
        # Layer 3: APT correlation
        if 3 in layers and scanners['layer3']:
            l3_result = scanners['layer3'].correlate_threat(
                file_hash, file_path, {}
            )
            result["details"]["layer3"] = l3_result
            result["risk_score"] = l3_result.get("apt_score", 0)
        
        scan_status[scan_id]["progress"] = 70
        
        # Deep learning classifier (for images)
        if enable_deep_learning and scanners['dl_classifier']:
            try:
                dl_result = scanners['dl_classifier'].predict(file_path)
                result["details"]["deep_learning"] = dl_result
                if dl_result.get("is_malicious", False):
                    result["is_malicious"] = True
                    result["confidence"] = max(result["confidence"], dl_result.get("confidence", 0))
            except Exception as e:
                logger.warning(f\"Deep learning analysis skipped: {e}\")
        
        scan_status[scan_id]["progress"] = 80
        
        # Behavioral analysis
        if enable_behavioral and scanners['behavioral']:
            behavioral_result = scanners['behavioral'].analyze_file(
                file_path, execute=False
            )
            result["details"]["behavioral"] = behavioral_result
            if behavioral_result.get("analysis", {}).get("is_suspicious", False):
                result["is_malicious"] = True
        
        scan_status[scan_id]["progress"] = 90
        
        # Threat intelligence
        if enable_threat_intel and scanners['threat_intel']:
            ti_result = scanners['threat_intel'].query_all_sources(file_hash)
            result["details"]["threat_intelligence"] = ti_result
            if ti_result.get("aggregated", {}).get("is_malicious", False):
                result["is_malicious"] = True
                result["confidence"] = max(
                    result["confidence"],
                    ti_result["aggregated"].get("confidence", 0)
                )
        
        # File parser (for documents)
        if scanners['file_parser'] and scanners['file_parser'].is_supported(file_path):
            parser_result = scanners['file_parser'].parse_file(file_path)
            result["details"]["file_parser"] = parser_result
            if parser_result.get("risk_score", 0) > 0.5:
                result["is_malicious"] = True
        
        # Finalize
        scan_status[scan_id]["progress"] = 100
        scan_status[scan_id]["status"] = "completed"
        scan_status[scan_id]["completed_at"] = datetime.now().isoformat()
        
        scan_results[scan_id] = result
        
        logger.info(f\"Scan {scan_id} completed: malicious={result['is_malicious']}\")
    
    except Exception as e:
        logger.error(f\"Scan {scan_id} failed: {e}\")
        scan_status[scan_id]["status"] = "failed"
        scan_status[scan_id]["error"] = str(e)


# Main entry point
if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print("FastAPI not available. Install with: pip install fastapi uvicorn")
        sys.exit(1)
    
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
