"""
Scanner logic for antivirus app. Integrates with ClamAV or YARA.
"""
import os
import shutil
import tempfile
from datetime import datetime

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: YARA not available. Installing without YARA support.")

class Scanner:
    def __init__(self):
        self.quarantine_dir = os.path.join(tempfile.gettempdir(), 'av_quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.rules = None
        
        # Initialize YARA rules if available
        if YARA_AVAILABLE:
            try:
                rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules', 'malware_rules.yar')
                self.rules = yara.compile(filepath=rules_path)
            except Exception as e:
                print(f"Warning: Could not load YARA rules: {e}")

    def scan_file(self, file_path):
        """Scan a single file for threats."""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
            
            # Basic file checks
            if os.path.getsize(file_path) == 0:
                return False, "Empty file"

            # YARA scan if available
            if YARA_AVAILABLE and self.rules:
                try:
                    matches = self.rules.match(file_path)
                    if matches:
                        return True, f"Matched YARA rule: {matches[0].rule}"
                except Exception as e:
                    return False, f"YARA scan error: {str(e)}"
                    
            # Basic file analysis if YARA is not available
            # Check file extension
            suspicious_extensions = {'.exe', '.dll', '.bat', '.vbs', '.js'}
            if os.path.splitext(file_path)[1].lower() in suspicious_extensions:
                return True, "Suspicious file extension detected"

            return False, "No threats detected"
        except Exception as e:
            return False, f"Scan error: {str(e)}"

    def scan_directory(self, directory):
        """Recursively scan a directory for threats."""
        results = []
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    is_threat, details = self.scan_file(file_path)
                    results.append({
                        'file': file_path,
                        'is_threat': is_threat,
                        'details': details
                    })
            return results
        except Exception as e:
            return [{'file': directory, 'is_threat': False, 'details': f"Scan error: {str(e)}"}]

    def quarantine_file(self, file_path):
        """Move potentially malicious file to quarantine."""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"

            # Create quarantine filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{os.path.basename(file_path)}_{timestamp}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            return True, quarantine_path
        except Exception as e:
            return False, f"Quarantine error: {str(e)}"

    def delete_file(self, file_path):
        """Securely delete a file."""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"

            # Securely overwrite file before deletion
            with open(file_path, 'wb') as f:
                f.write(os.urandom(os.path.getsize(file_path)))
            
            os.remove(file_path)
            return True, "File deleted successfully"
        except Exception as e:
            return False, f"Delete error: {str(e)}"
