"""
Quick Start Script for EDR System
This script helps set up and run the EDR system.
"""
import sys
import os
from pathlib import Path

def main():
    print("=" * 60)
    print("   EDR SYSTEM - Three-Layered Triage Architecture")
    print("=" * 60)
    print()
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("ERROR: Python 3.8 or higher is required.")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    
    print(f"✓ Python version: {sys.version.split()[0]}")
    
    # Check if we're in the right directory
    current_dir = Path.cwd()
    app_dir = current_dir / 'app'
    data_dir = current_dir / 'data'
    
    if not app_dir.exists():
        print("ERROR: 'app' directory not found.")
        print("Please run this script from the project root directory.")
        sys.exit(1)
    
    print(f"✓ Project directory: {current_dir}")
    
    # Check dependencies
    print("\nChecking dependencies...")
    
    required_modules = {
        'PyQt5': 'PyQt5',
        'sklearn': 'scikit-learn',
        'numpy': 'numpy',
        'yara': 'yara-python',
    }
    
    missing_modules = []
    
    for module_name, package_name in required_modules.items():
        try:
            __import__(module_name)
            print(f"✓ {package_name}")
        except ImportError:
            print(f"✗ {package_name} (missing)")
            missing_modules.append(package_name)
    
    # Optional dependencies
    optional_modules = {
        'pyclamd': 'pyclamd (ClamAV)',
        'ssdeep': 'ssdeep',
        'requests': 'requests'
    }
    
    for module_name, display_name in optional_modules.items():
        try:
            __import__(module_name)
            print(f"✓ {display_name}")
        except ImportError:
            print(f"⚠ {display_name} (optional)")
    
    if missing_modules:
        print("\nMissing required dependencies!")
        print("Install them with:")
        print(f"  pip install {' '.join(missing_modules)}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("All required dependencies installed!")
    print("=" * 60)
    
    # Check data directories
    print("\nSetting up data directories...")
    
    directories = [
        data_dir / 'yara_rules',
        data_dir / 'quarantine',
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ {directory.relative_to(current_dir)}")
    
    # Check YARA rules
    yara_rules_dir = data_dir / 'yara_rules'
    yara_files = list(yara_rules_dir.glob('*.yar')) + list(yara_rules_dir.glob('*.yara'))
    
    if yara_files:
        print(f"\n✓ Found {len(yara_files)} YARA rule file(s)")
    else:
        print("\n⚠ No YARA rules found in data/yara_rules/")
        print("  Sample rules have been created in: data/yara_rules/sample_rules.yar")
    
    # Launch application
    print("\n" + "=" * 60)
    print("Launching EDR System...")
    print("=" * 60 + "\n")
    
    try:
        # Add app directory to path
        sys.path.insert(0, str(app_dir))
        
        # Import and run the main window
        from main_window import main as run_app
        run_app()
    
    except Exception as e:
        print(f"\nERROR launching application: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
