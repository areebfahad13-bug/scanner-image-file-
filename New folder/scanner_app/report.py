"""
Scan report generation for antivirus app.
"""
import os
import json
from datetime import datetime

class ScanReport:
    def __init__(self):
        self.results = []
        self.start_time = datetime.now()
        self.reports_dir = "scan_reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def add_result(self, file_path, status, details=None):
        """Add a scan result to the report."""
        self.results.append({
            'file': file_path,
            'status': status,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })

    def generate_report(self):
        """Generate a detailed scan report."""
        report = {
            'scan_start': self.start_time.isoformat(),
            'scan_end': datetime.now().isoformat(),
            'total_files': len(self.results),
            'threats_found': sum(1 for r in self.results if r['status'] == 'THREAT'),
            'results': self.results
        }
        
        # Save report to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.reports_dir, f"scan_report_{timestamp}.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
            
        return report

    def get_summary(self):
        """Get a summary of the scan results."""
        total_files = len(self.results)
        threats = sum(1 for r in self.results if r['status'] == 'THREAT')
        clean = total_files - threats
        
        return {
            'total_files': total_files,
            'threats': threats,
            'clean': clean,
            'duration': (datetime.now() - self.start_time).total_seconds()
        }
