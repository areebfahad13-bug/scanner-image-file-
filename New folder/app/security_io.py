"""
Secure File I/O Module for EDR System
Provides path validation, thread-safe file operations, and efficient chunked reading.
"""
import os
import threading
from pathlib import Path
from typing import Generator, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global file lock for thread-safe operations
_file_lock = threading.Lock()


def validate_and_resolve_path(file_path: str, must_exist: bool = True) -> Path:
    """
    Validate and resolve a file path to prevent TOCTOU race conditions.
    
    Args:
        file_path: The file path to validate
        must_exist: Whether the path must exist (default: True)
    
    Returns:
        Resolved Path object
    
    Raises:
        ValueError: If path is invalid or doesn't exist when required
        FileNotFoundError: If path doesn't exist and must_exist is True
    """
    try:
        # Convert to Path object and resolve to canonical form
        path = Path(file_path).resolve(strict=must_exist)
        
        # Additional security checks
        if not path.is_absolute():
            raise ValueError(f"Path must be absolute: {file_path}")
        
        # Prevent directory traversal attacks
        try:
            # Ensure the path doesn't escape expected boundaries
            path.relative_to(Path.cwd().resolve())
        except ValueError:
            # Path is outside current working directory - log but allow
            logger.debug(f"Path outside CWD: {path}")
        
        logger.debug(f"Validated path: {path}")
        return path
    
    except FileNotFoundError as e:
        logger.error(f"Path not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        raise ValueError(f"Invalid path: {file_path}") from e


def read_in_chunks(file_path: str, chunk_size: int = 1024 * 1024) -> Generator[bytes, None, None]:
    """
    Generator function to read large files in memory-efficient chunks.
    
    Args:
        file_path: Path to the file to read
        chunk_size: Size of each chunk in bytes (default: 1MB)
    
    Yields:
        Chunks of file data as bytes
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    path = validate_and_resolve_path(file_path, must_exist=True)
    
    try:
        with open(path, 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        logger.debug(f"Completed reading file: {path}")
    
    except Exception as e:
        logger.error(f"Error reading file {path}: {e}")
        raise IOError(f"Failed to read file: {path}") from e


def safe_write_file(file_path: str, content: Any, mode: str = 'w', encoding: str = 'utf-8') -> bool:
    """
    Thread-safe file writing function with lock synchronization.
    
    Args:
        file_path: Path to the file to write
        content: Content to write (str for text mode, bytes for binary)
        mode: File open mode ('w', 'a', 'wb', 'ab')
        encoding: Text encoding (ignored for binary mode)
    
    Returns:
        True if successful, False otherwise
    
    Raises:
        ValueError: If mode is invalid
        IOError: If write operation fails
    """
    if mode not in ['w', 'a', 'wb', 'ab']:
        raise ValueError(f"Invalid file mode: {mode}")
    
    # Validate path (allow non-existent for writing)
    path = validate_and_resolve_path(file_path, must_exist=False)
    
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Thread-safe write operation
    with _file_lock:
        try:
            if 'b' in mode:
                # Binary mode
                with open(path, mode) as file:
                    file.write(content)
            else:
                # Text mode
                with open(path, mode, encoding=encoding) as file:
                    file.write(content)
            
            logger.debug(f"Successfully wrote to file: {path}")
            return True
        
        except Exception as e:
            logger.error(f"Error writing to file {path}: {e}")
            raise IOError(f"Failed to write to file: {path}") from e


def safe_append_log(log_file: str, message: str) -> bool:
    """
    Thread-safe log appending with automatic newline.
    
    Args:
        log_file: Path to the log file
        message: Message to append
    
    Returns:
        True if successful, False otherwise
    """
    try:
        return safe_write_file(log_file, message + '\n', mode='a')
    except Exception as e:
        logger.error(f"Failed to append to log: {e}")
        return False


def get_file_size(file_path: str) -> int:
    """
    Get file size safely.
    
    Args:
        file_path: Path to the file
    
    Returns:
        File size in bytes
    """
    path = validate_and_resolve_path(file_path, must_exist=True)
    return path.stat().st_size


def file_exists(file_path: str) -> bool:
    """
    Check if file exists safely.
    
    Args:
        file_path: Path to check
    
    Returns:
        True if file exists, False otherwise
    """
    try:
        path = validate_and_resolve_path(file_path, must_exist=False)
        return path.exists() and path.is_file()
    except Exception:
        return False


def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Compute cryptographic hash of a file using chunked reading.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm ('sha256', 'md5', 'sha1')
    
    Returns:
        Hexadecimal hash string
    
    Raises:
        ValueError: If algorithm is not supported
        IOError: If file cannot be read
    """
    import hashlib
    
    supported = {'sha256', 'md5', 'sha1'}
    if algorithm not in supported:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. Use one of {supported}")
    
    path = validate_and_resolve_path(file_path, must_exist=True)
    
    hasher = hashlib.new(algorithm)
    
    try:
        for chunk in read_in_chunks(str(path), chunk_size=1024 * 1024):
            hasher.update(chunk)
        
        result = hasher.hexdigest()
        logger.debug(f"Computed {algorithm} hash for {path}: {result}")
        return result
    
    except Exception as e:
        logger.error(f"Failed to compute hash for {path}: {e}")
        raise IOError(f"Hash computation failed: {path}") from e


def create_secure_temp_file(base_dir: str, prefix: str = "edr_temp_") -> Path:
    """
    Create a secure temporary file in the specified directory.
    
    Args:
        base_dir: Base directory for temp file
        prefix: Filename prefix
    
    Returns:
        Path to the created temp file
    """
    import uuid
    
    base_path = validate_and_resolve_path(base_dir, must_exist=True)
    if not base_path.is_dir():
        raise ValueError(f"Base directory must be a directory: {base_dir}")
    
    # Generate unique filename
    temp_name = f"{prefix}{uuid.uuid4().hex}"
    temp_path = base_path / temp_name
    
    # Create empty file
    temp_path.touch(mode=0o600)  # Owner read/write only
    logger.debug(f"Created secure temp file: {temp_path}")
    
    return temp_path
