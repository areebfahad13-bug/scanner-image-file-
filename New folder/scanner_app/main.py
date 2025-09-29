"""
Main entry point for the Antivirus Scanner App.
"""
import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QPushButton, QLabel, QFileDialog, QTextEdit, 
                           QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from scanner import Scanner
from report import ScanReport

class ScanWorker(QThread):
    """Worker thread for scanning to prevent GUI freeze."""
    progress = pyqtSignal(dict)
    finished = pyqtSignal(list)

    def __init__(self, scanner, directory):
        super().__init__()
        self.scanner = scanner
        self.directory = directory

    def run(self):
        results = self.scanner.scan_directory(self.directory)
        self.finished.emit(results)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = Scanner()
        self.report = ScanReport()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Antivirus Scanner')
        self.setMinimumSize(800, 600)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create UI elements
        self.scan_btn = QPushButton('Select Directory to Scan')
        self.scan_btn.clicked.connect(self.select_directory)

        self.progress_bar = QProgressBar()
        self.progress_bar.hide()

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)

        # Add elements to layout
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(QLabel('Scan Log:'))
        layout.addWidget(self.log_text)

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if directory:
            self.start_scan(directory)

    def start_scan(self, directory):
        self.scan_btn.setEnabled(False)
        self.progress_bar.show()
        self.log_text.clear()
        self.log_text.append(f"Starting scan of: {directory}\n")

        # Create and start worker thread
        self.scan_worker = ScanWorker(self.scanner, directory)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()

    def scan_finished(self, results):
        self.scan_btn.setEnabled(True)
        self.progress_bar.hide()

        # Process results
        threats_found = sum(1 for r in results if r['is_threat'])
        
        # Update report
        for result in results:
            self.report.add_result(result['file'], 
                                 'THREAT' if result['is_threat'] else 'CLEAN',
                                 result['details'])
            
            # Log results
            status = '🔴 THREAT' if result['is_threat'] else '🟢 CLEAN'
            self.log_text.append(f"{status}: {result['file']}")
            self.log_text.append(f"Details: {result['details']}\n")

        # Show summary
        if threats_found > 0:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Warning)
            msg.setText(f"Found {threats_found} potential threats!")
            msg.setInformativeText("Would you like to quarantine the threats?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            
            if msg.exec_() == QMessageBox.Yes:
                self.quarantine_threats(results)

    def quarantine_threats(self, results):
        threats = [r['file'] for r in results if r['is_threat']]
        for file_path in threats:
            success, details = self.scanner.quarantine_file(file_path)
            if success:
                self.log_text.append(f"✅ Quarantined: {file_path}")
            else:
                self.log_text.append(f"❌ Quarantine failed: {file_path} - {details}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
