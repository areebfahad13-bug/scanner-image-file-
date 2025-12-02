"""Pipeline controller for EDR scanner.

Implements Phase 1: file discovery producer, multiple worker processes
for Layer 1 and Layer 2 analysis, an APT worker (I/O-bound, rate-limited),
and a results aggregator that writes to SQLite in batches.

Designed to be robust when optional dependencies (yara, clamav, tensorflow)
are not installed: workers will log warnings and continue.
"""
import os
import time
import sqlite3
import logging
from pathlib import Path
from multiprocessing import Process, Event, Manager
from threading import Thread
from typing import List, Dict, Any, Optional

from .security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def discover_files(directories: List[str], file_queue, stop_event: Event, num_workers: int):
    """Walk directories and enqueue candidate files.

    After discovery completes, push `None` sentinel `num_workers` times to
    signal completion to workers.
    """
    try:
        for d in directories:
            try:
                base = validate_and_resolve_path(d, must_exist=True)
            except Exception as e:
                logger.warning(f"Skipping discovery path {d}: {e}")
                continue

            for p in base.rglob('*'):
                if stop_event.is_set():
                    logger.info("Discovery stopped by stop_event")
                    break
                if not p.is_file():
                    continue

                # Basic candidate filtering
                try:
                    stat = p.stat()
                    # Skip zero-length files
                    if stat.st_size == 0:
                        continue

                    file_info = {
                        'path': str(p),
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                    }
                    file_queue.put(file_info)

                except Exception as e:
                    logger.debug(f"Failed to stat file {p}: {e}")

            if stop_event.is_set():
                break

    finally:
        # Signal workers no more files
        logger.info("Discovery complete, sending sentinels to workers")
        for _ in range(num_workers):
            file_queue.put(None)


def scan_worker(worker_id: int, file_queue, results_queue, apt_queue, config: Dict[str, Any], stop_event: Event):
    """Worker process performing Layer 1 and Layer 2 sequentially for files."""
    logger.info(f"Worker {worker_id} starting")

    # Lazy imports to keep process startup smooth
    try:
        from .layer1_scanner import Layer1Scanner
    except Exception:
        Layer1Scanner = None

    try:
        from .layer2_apsa import Layer2APSA
    except Exception:
        Layer2APSA = None

    # Initialize scanners if available
    l1 = None
    if Layer1Scanner:
        try:
            l1 = Layer1Scanner(yara_rules_dir=config.get('yara_rules_dir'))
        except Exception as e:
            logger.warning(f"Worker {worker_id}: failed to init Layer1Scanner: {e}")

    l2 = None
    if Layer2APSA:
        try:
            l2 = Layer2APSA(ml_model_path=config.get('ml_model_path'), yara_rules_dir=config.get('yara_rules_dir'))
        except Exception as e:
            logger.warning(f"Worker {worker_id}: failed to init Layer2APSA: {e}")

    # Local batch buffer for potential future batching
    local_batch = []

    while not stop_event.is_set():
        file_info = file_queue.get()
        if file_info is None:
            logger.info(f"Worker {worker_id} received sentinel, exiting")
            # Re-propagate sentinel for other consumers if needed
            file_queue.put(None)
            break

        path = file_info.get('path')
        logger.info(f"Worker {worker_id} processing: {path}")

        # Compute SHA256 hash for APT correlation and VT lookups
        file_hash = None
        try:
            from .security_io import compute_file_hash
            file_hash = compute_file_hash(path, algorithm='sha256')
        except Exception as e:
            logger.warning(f"Worker {worker_id}: Failed to compute hash for {path}: {e}")

        result = {
            'path': path,
            'sha256': file_hash,
            'timestamp': time.time(),
            'layer1': None,
            'layer2': None,
            'layer3': None,
            'final_score': 0.0,
        }

        # Layer 1
        try:
            if l1:
                is_threat, confidence, details = l1.scan_file(path)
                result['layer1'] = details
                if is_threat:
                    result['final_score'] = max(result['final_score'], confidence * 0.30)
                    # Send to apt_queue for correlation
                    apt_queue.put({'path': path, 'sha256': file_hash, 'prior': result})
                    results_queue.put(result)
                    continue
        except Exception as e:
            logger.exception(f"Worker {worker_id} Layer1 error for {path}: {e}")

        # Layer 2
        try:
            if l2:
                score, details = l2.analyze_file(path)
                result['layer2'] = details
                result['final_score'] = max(result['final_score'], score * 0.35)
                if details.get('is_anomaly'):
                    apt_queue.put({'path': path, 'sha256': file_hash, 'prior': result})

        except Exception as e:
            logger.exception(f"Worker {worker_id} Layer2 error for {path}: {e}")

        # Push result
        results_queue.put(result)

    logger.info(f"Worker {worker_id} stopped")


def apt_worker(apt_queue, results_queue, db_path: str, vt_api_key: Optional[str], stop_event: Event, rate_limit: float = 15.0):
    """APT / Threat Intel worker that performs rate-limited lookups and writes to DB."""
    logger.info("APT worker starting")

    # Lazy import
    try:
        from .threat_intelligence import ThreatIntelligence
    except Exception:
        ThreatIntelligence = None

    ti = None
    if ThreatIntelligence and vt_api_key:
        try:
            ti = ThreatIntelligence(vt_api_key=vt_api_key)
        except Exception as e:
            logger.warning(f"Failed to init ThreatIntelligence: {e}")

    # Initialize DB for APT writes (only this worker will write)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')  # Faster than FULL, still safe with WAL
    cursor.execute('PRAGMA cache_size=-64000')  # 64MB cache
    cursor.execute('PRAGMA temp_store=MEMORY')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS apt_results (
            path TEXT PRIMARY KEY,
            sha256 TEXT,
            result TEXT,
            timestamp REAL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_apt_sha256 ON apt_results(sha256)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_apt_timestamp ON apt_results(timestamp)')
    conn.commit()
    
    logger.info("APT worker DB initialized with WAL mode")

    last_request = 0.0

    while not stop_event.is_set():
        task = apt_queue.get()
        if task is None:
            logger.info("APT worker received sentinel, exiting")
            apt_queue.put(None)
            break

        path = task.get('path')
        sha256 = task.get('sha256')
        prior = task.get('prior')

        # Rate limiting
        elapsed = time.time() - last_request
        if elapsed < rate_limit:
            wait = rate_limit - elapsed
            logger.debug(f"APT worker sleeping {wait:.1f}s to respect rate limit")
            time.sleep(wait)

        intel = None
        if ti and sha256:
            try:
                logger.info(f"APT worker querying threat intel for {path} (hash: {sha256[:16]}...)")
                intel = ti.query_all_sources(sha256)
                if intel:
                    logger.info(f"APT intel result for {path}: threat_level={intel.get('aggregated', {}).get('threat_level', 'unknown')}")
            except Exception as e:
                logger.warning(f"APT lookup failed for {path}: {e}")
        elif not sha256:
            logger.debug(f"APT worker: no hash available for {path}, skipping threat intel")

        # Simple DB write (cache)
        try:
            cursor.execute('INSERT OR REPLACE INTO apt_results (path, sha256, result, timestamp) VALUES (?, ?, ?, ?)',
                           (path, sha256, str(intel or {}), time.time()))
            conn.commit()
        except Exception as e:
            logger.warning(f"Failed to write APT result for {path}: {e}")

        # Emit updated result (simple augmentation)
        update = {'path': path, 'layer3': intel}
        results_queue.put(update)
        last_request = time.time()

    conn.close()
    logger.info("APT worker stopped")


def result_aggregator(results_queue, db_path: str, stop_event: Event, batch_size: int = 50, progress_callback=None):
    """Aggregator that writes results to SQLite in batches and maintains in-memory state.
    
    Args:
        progress_callback: Optional callable(stats_dict) for GUI progress updates
    """
    logger.info("Result aggregator starting")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')
    cursor.execute('PRAGMA cache_size=-64000')  # 64MB cache
    cursor.execute('PRAGMA temp_store=MEMORY')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            path TEXT PRIMARY KEY,
            payload TEXT,
            last_seen REAL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(last_seen)')
    conn.commit()
    
    logger.info("Aggregator DB initialized with WAL mode")

    pending = []
    file_states = {}
    stats = {'files_scanned': 0, 'threats_found': 0, 'avg_score': 0.0, 'last_update': time.time()}

    while not stop_event.is_set():
        try:
            item = results_queue.get(timeout=1)
        except Exception:
            item = None

        if item is None:
            # Check if we should exit: continue until sentinel seen
            continue

        # Merge updates
        path = item.get('path')
        if not path:
            continue

        state = file_states.get(path, {'path': path, 'layers': {}})
        # Merge layer entries
        for k in ['layer1', 'layer2', 'layer3']:
            if k in item and item[k] is not None:
                state['layers'][k] = item[k]

        if 'final_score' in item:
            state['final_score'] = item['final_score']

        file_states[path] = state
        pending.append((path, str(state), time.time()))
        
        # Update statistics
        stats['files_scanned'] = len(file_states)
        final_score = state.get('final_score', 0)
        if final_score >= 0.6:
            stats['threats_found'] = sum(1 for s in file_states.values() if s.get('final_score', 0) >= 0.6)
        
        # Calculate average score
        scores = [s.get('final_score', 0) for s in file_states.values() if 'final_score' in s]
        stats['avg_score'] = sum(scores) / len(scores) if scores else 0.0
        stats['last_update'] = time.time()
        
        # Emit progress callback
        if progress_callback and time.time() - stats.get('last_callback', 0) > 0.5:
            try:
                progress_callback(stats.copy())
                stats['last_callback'] = time.time()
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

        # Batch commit
        if len(pending) >= batch_size:
            try:
                cursor.executemany('INSERT OR REPLACE INTO scan_results (path, payload, last_seen) VALUES (?, ?, ?)', pending)
                conn.commit()
                logger.info(f"Committed {len(pending)} results to DB")
            except Exception as e:
                logger.warning(f"Aggregator DB commit failed: {e}")
            pending = []

    # Flush remaining
    if pending:
        try:
            cursor.executemany('INSERT OR REPLACE INTO scan_results (path, payload, last_seen) VALUES (?, ?, ?)', pending)
            conn.commit()
            logger.info(f"Committed final {len(pending)} results to DB")
        except Exception as e:
            logger.warning(f"Final DB commit failed: {e}")

    conn.close()
    logger.info("Result aggregator stopped")


class PipelineController:
    def __init__(self, num_workers: Optional[int] = None, ml_batch_size: int = 16, yara_rules_dir: Optional[str] = None, ml_model_path: Optional[str] = None, db_path: str = 'data/events_db.sqlite', vt_api_key: Optional[str] = None, progress_callback=None):
        self.num_workers = num_workers or max(1, (os.cpu_count() or 2) - 1)
        self.ml_batch_size = ml_batch_size
        self.yara_rules_dir = yara_rules_dir
        self.ml_model_path = ml_model_path
        self.db_path = db_path
        self.vt_api_key = vt_api_key
        self.progress_callback = progress_callback

        self.manager = Manager()
        self.file_queue = self.manager.Queue()
        self.results_queue = self.manager.Queue()
        self.apt_queue = self.manager.Queue()

        self.stop_event = Event()

        self.producer_thread = None
        self.worker_processes: List[Process] = []
        self.apt_processes: List[Process] = []
        self.aggregator_thread = None

    def start_scan(self, directories: List[str]):
        # Ensure DB directory
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        # Start producer
        self.producer_thread = Thread(target=discover_files, args=(directories, self.file_queue, self.stop_event, self.num_workers), daemon=True)
        self.producer_thread.start()

        # Start workers
        for i in range(self.num_workers):
            p = Process(target=scan_worker, args=(i, self.file_queue, self.results_queue, self.apt_queue, {
                'yara_rules_dir': self.yara_rules_dir,
                'ml_model_path': self.ml_model_path,
            }, self.stop_event))
            p.start()
            self.worker_processes.append(p)

        # Start APT worker (single process)
        apt_p = Process(target=apt_worker, args=(self.apt_queue, self.results_queue, self.db_path + '.apt', self.vt_api_key, self.stop_event))
        apt_p.start()
        self.apt_processes.append(apt_p)

        # Start aggregator thread
        self.aggregator_thread = Thread(target=result_aggregator, args=(self.results_queue, self.db_path, self.stop_event, 50, self.progress_callback), daemon=True)
        self.aggregator_thread.start()

        logger.info("Pipeline started")

    def stop_scan(self):
        logger.info("Stopping pipeline")
        self.stop_event.set()

        # Send sentinels
        for _ in range(self.num_workers):
            self.file_queue.put(None)
        self.apt_queue.put(None)

        # Join threads/processes
        if self.producer_thread:
            self.producer_thread.join(timeout=5)

        for p in self.worker_processes:
            p.join(timeout=5)

        for p in self.apt_processes:
            p.join(timeout=5)

        if self.aggregator_thread:
            # aggregator polls on results_queue; give it a moment
            time.sleep(1)

        logger.info("Pipeline stopped")
