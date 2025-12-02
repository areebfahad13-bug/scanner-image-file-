"""
Least Privilege Remediation Helper
Handles Quarantine and Delete operations with strict security controls.
Implements Principle of Least Privilege (PoLP) using subprocess isolation.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Tuple, List
import logging
import hashlib

from .security_io import validate_and_resolve_path, safe_write_file

logger = logging.getLogger(__name__)


class RemediationError(Exception):
    """Custom exception for remediation operations."""
    pass


def validate_action(action: str) -> bool:
    """
    Validate that the action is one of the allowed operations.
    
    Args:
        action: The action to validate
    
    Returns:
        True if valid, raises ValueError otherwise
    """
    allowed_actions = ['quarantine', 'delete', 'restore']
    if action.lower() not in allowed_actions:
        raise ValueError(f"Invalid action: {action}. Must be one of {allowed_actions}")
    return True


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate cryptographic hash of a file for verification.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
    
    Returns:
        Hexadecimal hash string
    """
    path = validate_and_resolve_path(file_path, must_exist=True)
    
    hash_obj = hashlib.new(algorithm)
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def quarantine_file(file_path: str, quarantine_dir: str, metadata: dict = None) -> Tuple[bool, str]:
    """
    Quarantine a file by moving it to a secure location.
    
    Args:
        file_path: Path to the file to quarantine
        quarantine_dir: Directory to quarantine files
        metadata: Optional metadata about the threat
    
    Returns:
        Tuple of (success: bool, message/new_path: str)
    """
    try:
        # Validate paths
        source_path = validate_and_resolve_path(file_path, must_exist=True)
        quarantine_path = validate_and_resolve_path(quarantine_dir, must_exist=False)
        
        # Ensure quarantine directory exists with restricted permissions
        quarantine_path.mkdir(parents=True, exist_ok=True)
        
        # Generate quarantine filename with timestamp and hash
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = calculate_file_hash(str(source_path))[:16]
        quarantine_name = f"{source_path.name}_{timestamp}_{file_hash}.quarantine"
        destination = quarantine_path / quarantine_name
        
        # Save metadata
        metadata_file = destination.with_suffix('.metadata')
        metadata_content = {
            'original_path': str(source_path),
            'quarantine_date': datetime.now().isoformat(),
            'file_size': source_path.stat().st_size,
            'file_hash': file_hash,
            'threat_info': metadata or {}
        }
        
        import json
        safe_write_file(str(metadata_file), json.dumps(metadata_content, indent=2))
        
        # Move file to quarantine
        shutil.move(str(source_path), str(destination))
        
        logger.info(f"Quarantined: {source_path} -> {destination}")
        return True, str(destination)
    
    except Exception as e:
        logger.error(f"Quarantine failed for {file_path}: {e}")
        return False, str(e)


def delete_file_secure(file_path: str, overwrite_passes: int = 3) -> Tuple[bool, str]:
    """
    Securely delete a file by overwriting before deletion.
    
    Args:
        file_path: Path to the file to delete
        overwrite_passes: Number of overwrite passes (default: 3)
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        path = validate_and_resolve_path(file_path, must_exist=True)
        file_size = path.stat().st_size
        
        # Overwrite file multiple times
        with open(path, 'rb+') as f:
            for pass_num in range(overwrite_passes):
                f.seek(0)
                # Alternate patterns for better security
                if pass_num % 2 == 0:
                    f.write(os.urandom(file_size))
                else:
                    f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
        
        # Delete the file
        os.remove(path)
        
        logger.info(f"Securely deleted: {path}")
        return True, f"File securely deleted: {path}"
    
    except Exception as e:
        logger.error(f"Secure delete failed for {file_path}: {e}")
        return False, str(e)


def restore_file(quarantine_path: str) -> Tuple[bool, str]:
    """
    Restore a file from quarantine to its original location.
    
    Args:
        quarantine_path: Path to the quarantined file
    
    Returns:
        Tuple of (success: bool, message/restored_path: str)
    """
    try:
        import json
        
        qpath = validate_and_resolve_path(quarantine_path, must_exist=True)
        metadata_file = qpath.with_suffix('.metadata')
        
        if not metadata_file.exists():
            return False, "Metadata file not found"
        
        # Read metadata
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        original_path = Path(metadata['original_path'])
        
        # Ensure parent directory exists
        original_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move file back
        shutil.move(str(qpath), str(original_path))
        
        # Remove metadata file
        metadata_file.unlink()
        
        logger.info(f"Restored: {qpath} -> {original_path}")
        return True, str(original_path)
    
    except Exception as e:
        logger.error(f"Restore failed for {quarantine_path}: {e}")
        return False, str(e)


def execute_privileged_action(action: str, file_path: str, **kwargs) -> Tuple[bool, str]:
    """
    Execute a privileged remediation action with strict validation.
    This function serves as a controlled interface for sensitive operations.
    
    Args:
        action: Action to perform ('quarantine', 'delete', 'restore')
        file_path: Path to the target file
        **kwargs: Additional parameters (e.g., quarantine_dir for quarantine action)
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        # Validate action
        validate_action(action)
        
        # Validate file path
        path = validate_and_resolve_path(file_path, must_exist=True)
        
        # Build validated argument list
        action = action.lower()
        
        if action == 'quarantine':
            quarantine_dir = kwargs.get('quarantine_dir')
            if not quarantine_dir:
                raise ValueError("quarantine_dir required for quarantine action")
            
            metadata = kwargs.get('metadata', {})
            return quarantine_file(str(path), quarantine_dir, metadata)
        
        elif action == 'delete':
            overwrite_passes = kwargs.get('overwrite_passes', 3)
            return delete_file_secure(str(path), overwrite_passes)
        
        elif action == 'restore':
            return restore_file(str(path))
        
        else:
            raise ValueError(f"Unsupported action: {action}")
    
    except Exception as e:
        logger.error(f"Privileged action failed: {e}")
        return False, str(e)


def batch_quarantine(file_paths: List[str], quarantine_dir: str) -> dict:
    """
    Quarantine multiple files in batch.
    
    Args:
        file_paths: List of file paths to quarantine
        quarantine_dir: Directory to quarantine files
    
    Returns:
        Dictionary with success/failure counts and details
    """
    results = {
        'success': [],
        'failed': [],
        'total': len(file_paths)
    }
    
    for file_path in file_paths:
        success, message = execute_privileged_action(
            'quarantine',
            file_path,
            quarantine_dir=quarantine_dir
        )
        
        if success:
            results['success'].append({'file': file_path, 'new_path': message})
        else:
            results['failed'].append({'file': file_path, 'error': message})
    
    return results


# Helper script for subprocess execution (can be extracted to separate file)
def _remediation_subprocess_helper():
    """
    Helper function that can be called as a subprocess for privileged operations.
    This enables process isolation and least privilege execution.
    """
    if len(sys.argv) < 3:
        print("Usage: remediation_helper.py <action> <file_path> [options]")
        sys.exit(1)
    
    action = sys.argv[1]
    file_path = sys.argv[2]
    
    # Parse additional options
    options = {}
    for i in range(3, len(sys.argv), 2):
        if i + 1 < len(sys.argv):
            options[sys.argv[i]] = sys.argv[i + 1]
    
    success, message = execute_privileged_action(action, file_path, **options)
    
    if success:
        print(f"SUCCESS: {message}")
        sys.exit(0)
    else:
        print(f"FAILED: {message}")
        sys.exit(1)


if __name__ == "__main__":
    # Enable logging for standalone execution
    logging.basicConfig(level=logging.INFO)
    _remediation_subprocess_helper()
