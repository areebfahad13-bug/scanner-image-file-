"""
Extended File Parser Module
Supports parsing of PDF, Office documents (DOCX, XLSX, PPTX), and other complex file types.
Extracts metadata, embedded code, macros, and suspicious content.
"""
import os
import logging
import zipfile
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import hashlib

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

from security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Parse and analyze PDF files for embedded threats.
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'javascript', 'eval', 'unescape', 'fromcharcode',
            'exec', 'system', 'cmd', 'powershell', '/Launch', '/JS', '/JavaScript'
        ]
    
    def parse(self, file_path: str) -> Dict:
        """
        Parse PDF file and extract suspicious content.
        
        Args:
            file_path: Path to PDF file
        
        Returns:
            Dictionary with analysis results
        """
        if not PDF_AVAILABLE:
            return {'error': 'pdfminer not available', 'parsed': False}
        
        result = {
            'parsed': False,
            'file_type': 'pdf',
            'metadata': {},
            'text_content': '',
            'suspicious_elements': [],
            'embedded_files': 0,
            'javascript_found': False,
            'forms_found': False,
            'risk_score': 0.0
        }
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Extract text content
            try:
                text = pdf_extract_text(str(path))
                result['text_content'] = text[:5000] if text else ''  # First 5000 chars
            except Exception as e:
                logger.warning(f"PDF text extraction failed: {e}")
            
            # Parse PDF structure
            with open(path, 'rb') as f:
                parser = PDFParser(f)
                doc = PDFDocument(parser)
                
                # Extract metadata
                if doc.info:
                    for info in doc.info:
                        result['metadata'] = {
                            k.decode() if isinstance(k, bytes) else k: 
                            v.decode() if isinstance(v, bytes) else str(v)
                            for k, v in info.items()
                        }
                
                # Check for suspicious elements
                f.seek(0)
                content = f.read().decode('latin-1', errors='ignore')
                
                for keyword in self.suspicious_keywords:
                    if keyword.lower() in content.lower():
                        result['suspicious_elements'].append({
                            'type': 'keyword',
                            'value': keyword,
                            'risk': 'high' if keyword in ['javascript', 'exec', 'system'] else 'medium'
                        })
                        
                        if keyword.lower() in ['javascript', '/js']:
                            result['javascript_found'] = True
                
                # Check for embedded files
                if '/EmbeddedFile' in content or '/F ' in content:
                    result['embedded_files'] = content.count('/EmbeddedFile')
                    result['suspicious_elements'].append({
                        'type': 'embedded_files',
                        'count': result['embedded_files'],
                        'risk': 'high'
                    })
                
                # Check for forms
                if '/AcroForm' in content or '/XFA' in content:
                    result['forms_found'] = True
                    result['suspicious_elements'].append({
                        'type': 'interactive_forms',
                        'risk': 'medium'
                    })
            
            # Calculate risk score
            result['risk_score'] = self._calculate_risk(result)
            result['parsed'] = True
            
        except Exception as e:
            logger.error(f"PDF parsing failed for {file_path}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _calculate_risk(self, result: Dict) -> float:
        """Calculate risk score based on PDF features."""
        risk = 0.0
        
        if result['javascript_found']:
            risk += 0.4
        if result['embedded_files'] > 0:
            risk += 0.3
        if result['forms_found']:
            risk += 0.15
        
        # Suspicious keywords
        high_risk_elements = sum(
            1 for e in result['suspicious_elements'] 
            if e.get('risk') == 'high'
        )
        risk += min(0.3, high_risk_elements * 0.1)
        
        return min(1.0, risk)


class OfficeParser:
    """
    Parse Microsoft Office documents (DOCX, XLSX, PPTX) for macros and embedded content.
    """
    
    def __init__(self):
        self.suspicious_vba_keywords = [
            'AutoOpen', 'AutoClose', 'Document_Open', 'Workbook_Open',
            'Shell', 'CreateObject', 'WScript.Shell', 'Environ',
            'ExecuteExcel4Macro', 'RegisterXLL', 'Application.Run'
        ]
    
    def parse(self, file_path: str) -> Dict:
        """
        Parse Office document for threats.
        
        Args:
            file_path: Path to Office file
        
        Returns:
            Analysis results
        """
        result = {
            'parsed': False,
            'file_type': '',
            'has_macros': False,
            'macro_content': [],
            'external_links': [],
            'embedded_objects': 0,
            'suspicious_elements': [],
            'risk_score': 0.0
        }
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            extension = path.suffix.lower()
            
            # Determine file type
            if extension in ['.docx', '.docm']:
                result['file_type'] = 'word'
            elif extension in ['.xlsx', '.xlsm']:
                result['file_type'] = 'excel'
            elif extension in ['.pptx', '.pptm']:
                result['file_type'] = 'powerpoint'
            else:
                result['file_type'] = 'unknown'
            
            # Check if it's a valid ZIP (modern Office format)
            if not zipfile.is_zipfile(path):
                # Try old Office format with olefile
                if OLEFILE_AVAILABLE:
                    result.update(self._parse_old_office(str(path)))
                else:
                    result['error'] = 'Not a valid Office file or olefile not available'
                return result
            
            # Parse modern Office format
            with zipfile.ZipFile(path, 'r') as zip_file:
                file_list = zip_file.namelist()
                
                # Check for macros
                macro_files = [f for f in file_list if 'vbaProject' in f or f.endswith('.bin')]
                result['has_macros'] = len(macro_files) > 0
                
                if result['has_macros']:
                    result['suspicious_elements'].append({
                        'type': 'vba_macros',
                        'files': macro_files,
                        'risk': 'high'
                    })
                    
                    # Try to extract macro content
                    for macro_file in macro_files:
                        try:
                            content = zip_file.read(macro_file)
                            # Look for suspicious keywords
                            content_str = content.decode('latin-1', errors='ignore')
                            suspicious = [
                                kw for kw in self.suspicious_vba_keywords 
                                if kw.lower() in content_str.lower()
                            ]
                            if suspicious:
                                result['macro_content'].append({
                                    'file': macro_file,
                                    'suspicious_keywords': suspicious
                                })
                        except Exception as e:
                            logger.warning(f"Could not read macro file {macro_file}: {e}")
                
                # Check for external links
                rels_files = [f for f in file_list if f.endswith('.rels')]
                for rels_file in rels_files:
                    try:
                        content = zip_file.read(rels_file).decode('utf-8', errors='ignore')
                        # Extract URLs
                        urls = re.findall(r'Target="(https?://[^"]+)"', content)
                        result['external_links'].extend(urls)
                    except Exception:
                        pass
                
                if result['external_links']:
                    result['suspicious_elements'].append({
                        'type': 'external_links',
                        'count': len(result['external_links']),
                        'risk': 'medium'
                    })
                
                # Check for embedded objects
                embedded = [f for f in file_list if 'embeddings' in f.lower() or 'oleObject' in f]
                result['embedded_objects'] = len(embedded)
                
                if result['embedded_objects'] > 0:
                    result['suspicious_elements'].append({
                        'type': 'embedded_objects',
                        'count': result['embedded_objects'],
                        'risk': 'medium'
                    })
            
            # Calculate risk
            result['risk_score'] = self._calculate_risk(result)
            result['parsed'] = True
        
        except Exception as e:
            logger.error(f"Office document parsing failed for {file_path}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _parse_old_office(self, file_path: str) -> Dict:
        """Parse old Office format (.doc, .xls) using olefile."""
        result = {
            'format': 'old_office',
            'has_macros': False,
            'streams': []
        }
        
        if not OLEFILE_AVAILABLE:
            return result
        
        try:
            ole = olefile.OleFileIO(file_path)
            result['streams'] = ole.listdir()
            
            # Check for VBA macros
            if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                result['has_macros'] = True
                result['suspicious_elements'] = [{
                    'type': 'vba_macros',
                    'risk': 'high'
                }]
            
            ole.close()
        
        except Exception as e:
            logger.error(f"Old Office format parsing failed: {e}")
        
        return result
    
    def _calculate_risk(self, result: Dict) -> float:
        """Calculate risk score for Office documents."""
        risk = 0.0
        
        if result['has_macros']:
            risk += 0.5
            
            # Higher risk if suspicious keywords found
            if result['macro_content']:
                risk += min(0.3, len(result['macro_content']) * 0.1)
        
        if result['external_links']:
            risk += min(0.2, len(result['external_links']) * 0.05)
        
        if result['embedded_objects'] > 0:
            risk += min(0.2, result['embedded_objects'] * 0.05)
        
        return min(1.0, risk)


class ExtendedFileParser:
    """
    Main file parser that routes to appropriate specialized parsers.
    """
    
    def __init__(self):
        self.pdf_parser = PDFParser()
        self.office_parser = OfficeParser()
        
        self.supported_types = {
            '.pdf': self.pdf_parser,
            '.docx': self.office_parser,
            '.docm': self.office_parser,
            '.doc': self.office_parser,
            '.xlsx': self.office_parser,
            '.xlsm': self.office_parser,
            '.xls': self.office_parser,
            '.pptx': self.office_parser,
            '.pptm': self.office_parser,
            '.ppt': self.office_parser
        }
    
    def parse_file(self, file_path: str) -> Dict:
        """
        Parse file based on its type.
        
        Args:
            file_path: Path to file
        
        Returns:
            Parsing results
        """
        result = {
            'file': file_path,
            'supported': False,
            'parser_used': None
        }
        
        try:
            path = Path(file_path)
            extension = path.suffix.lower()
            
            if extension in self.supported_types:
                parser = self.supported_types[extension]
                result['supported'] = True
                result['parser_used'] = parser.__class__.__name__
                result.update(parser.parse(file_path))
            else:
                result['error'] = f'Unsupported file type: {extension}'
        
        except Exception as e:
            logger.error(f"File parsing failed for {file_path}: {e}")
            result['error'] = str(e)
        
        return result
    
    def get_supported_types(self) -> List[str]:
        """Get list of supported file extensions."""
        return list(self.supported_types.keys())
    
    def is_supported(self, file_path: str) -> bool:
        """Check if file type is supported."""
        extension = Path(file_path).suffix.lower()
        return extension in self.supported_types
