"""
ML Model Training Script
Train the IsolationForest model on benign baseline files.
"""
import sys
from pathlib import Path
from app.layer2_apsa import Layer2APSA
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def collect_benign_files(directory):
    """
    Collect benign files from a directory for training.
    
    Args:
        directory: Path to directory containing known benign files
    
    Returns:
        List of file paths
    """
    benign_files = []
    dir_path = Path(directory)
    
    if not dir_path.exists():
        logger.error(f"Directory not found: {directory}")
        return []
    
    # Collect various file types
    extensions = [
        '*.exe', '*.dll', '*.sys',  # Executables
        '*.pdf', '*.doc', '*.docx',  # Documents
        '*.txt', '*.log',            # Text files
        '*.zip', '*.rar',            # Archives
        '*.jpg', '*.png',            # Images
    ]
    
    for ext in extensions:
        for file_path in dir_path.rglob(ext):
            if file_path.is_file():
                benign_files.append(str(file_path))
    
    return benign_files


def train_model(benign_directory, output_model_path, yara_rules_dir=None):
    """
    Train the ML model on benign files.
    
    Args:
        benign_directory: Directory containing benign samples
        output_model_path: Path to save trained model
        yara_rules_dir: Optional YARA rules directory
    
    Returns:
        True if successful
    """
    logger.info("=" * 60)
    logger.info("ML Model Training")
    logger.info("=" * 60)
    
    # Initialize Layer 2
    logger.info("Initializing Layer 2 APSA...")
    layer2 = Layer2APSA(
        ml_model_path=None,
        yara_rules_dir=yara_rules_dir,
        anomaly_threshold=0.6
    )
    
    # Collect benign files
    logger.info(f"Collecting benign files from: {benign_directory}")
    benign_files = collect_benign_files(benign_directory)
    
    if not benign_files:
        logger.error("No benign files found!")
        return False
    
    logger.info(f"Found {len(benign_files)} benign files")
    
    # Train model
    logger.info("Training IsolationForest model...")
    logger.info("This may take several minutes depending on file count...")
    
    success = layer2.train_model(benign_files)
    
    if not success:
        logger.error("Training failed!")
        return False
    
    # Save model
    logger.info(f"Saving model to: {output_model_path}")
    success = layer2.save_model(output_model_path)
    
    if success:
        logger.info("=" * 60)
        logger.info("Training completed successfully!")
        logger.info("=" * 60)
        logger.info(f"Model saved to: {output_model_path}")
        logger.info("You can now use this model in the EDR system.")
        return True
    else:
        logger.error("Failed to save model!")
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Train ML model for EDR System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train on benign files in C:\\Benign
  python train_model.py C:\\Benign
  
  # Specify custom output location
  python train_model.py C:\\Benign --output data\\my_model.pkl
  
  # Include YARA rules directory
  python train_model.py C:\\Benign --yara-rules data\\yara_rules
        """
    )
    
    parser.add_argument(
        'benign_dir',
        help='Directory containing known benign files for training'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='data/ml_model.pkl',
        help='Output path for trained model (default: data/ml_model.pkl)'
    )
    
    parser.add_argument(
        '--yara-rules',
        default=None,
        help='Optional: YARA rules directory'
    )
    
    args = parser.parse_args()
    
    # Validate input directory
    if not Path(args.benign_dir).exists():
        print(f"ERROR: Directory not found: {args.benign_dir}")
        sys.exit(1)
    
    # Create output directory if needed
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Train model
    success = train_model(
        args.benign_dir,
        str(output_path),
        args.yara_rules
    )
    
    if success:
        print("\n✓ Training completed successfully!")
        print(f"✓ Model saved to: {output_path}")
        sys.exit(0)
    else:
        print("\n✗ Training failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
