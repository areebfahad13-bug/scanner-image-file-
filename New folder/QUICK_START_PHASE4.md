# Quick Start: Phase 4 GUI Integration

## What's New

✅ **Parallel Pipeline Mode** - Multi-process scanning with real-time updates  
✅ **Live Statistics** - Files scanned, threats found, average score  
✅ **Responsive UI** - No freezing during scans  
✅ **Database Results** - Persistent storage with SQLite WAL mode  

---

## How to Use

### 1. Start the GUI

```bash
cd "New folder"
python -m app.main_window
```

### 2. Select Directory

Click **"Select Directory to Scan"** and choose a folder

### 3. Watch Real-Time Updates

The GUI will show:
- **Risk Score Widget:** Average threat score (0-100%)
- **Log Window:** Progress updates every 10 files
- **Files Scanned Counter:** Total files processed
- **Progress Bar:** Pulsing animation during scan

### 4. View Results

When scan completes:
- Summary shown in log window
- Threat count displayed
- Results saved to `data/events_db.sqlite`

---

## Key Features

### Real-Time Updates (Every 0.5s)

```
Progress: 10 files | 0 threats | Avg score: 12.3%
Progress: 20 files | 1 threats | Avg score: 23.4%
Progress: 30 files | 1 threats | Avg score: 18.9%
```

### Color-Coded Risk Scores

| Score | Color | Status |
|-------|-------|--------|
| 0-30% | 🟢 Green | CLEAN |
| 30-60% | 🟠 Orange | SUSPICIOUS |
| 60-100% | 🔴 Red | THREAT |

### Stop Scan

Click **"Stop Scan"** button at any time for graceful shutdown

---

## Performance

| Workers | Speed | Files/sec |
|---------|-------|-----------|
| Auto (CPU-1) | Fast | ~8-10 |
| Manual (4) | Very Fast | ~11 |
| Manual (8) | Fastest | ~15 |

---

## Architecture

```
GUI (PyQt5)
  ↓
PipelineWorker (QThread)
  ↓
PipelineController (Multiprocessing)
  ↓
Workers × N (CPU cores)
  ↓
SQLite Database (WAL mode)
```

---

## Files Modified

- ✅ `app/pipeline_controller.py` - Added progress_callback
- ✅ `app/main_window.py` - Added PipelineWorker + GUI integration

---

## Configuration

### Toggle Modes

```python
# In main_window.py, line ~125
self.use_pipeline = True   # Parallel (fast)
self.use_pipeline = False  # Sequential (legacy)
```

### Change Worker Count

```python
# In PipelineController.__init__()
num_workers=4  # Explicit count
num_workers=None  # Auto-detect (CPU cores - 1)
```

---

## Troubleshooting

**No updates appearing?**
- Check console for errors
- Ensure `progress_callback` is set

**GUI freezing?**
- Verify PipelineWorker is QThread subclass
- Check you're calling `.start()` not `.run()`

**Database locked?**
- Run: `sqlite3 data/events_db.sqlite "PRAGMA journal_mode;"`
- Should return: `wal`

---

## What's Next?

✅ Phase 1-3: Core pipeline complete  
✅ Phase 4: GUI integration complete  
⏭️ Phase 5: Automated YARA generation  

---

**Status:** Phase 4 Complete! 🎉
