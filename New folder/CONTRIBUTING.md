# Contributing to EDR Scanner

Thank you for your interest in contributing to the EDR Scanner project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Contributing YARA Rules](#contributing-yara-rules)
- [Contributing ML Models](#contributing-ml-models)
- [Contributing Datasets](#contributing-datasets)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

There are many ways to contribute to this project:

### 1. Report Bugs

- Use the GitHub Issues tab
- Include detailed steps to reproduce
- Provide system information (OS, Python version, etc.)
- Include relevant logs and error messages

### 2. Suggest Enhancements

- Open a GitHub Issue with the "enhancement" label
- Clearly describe the feature and its benefits
- Provide use cases and examples

### 3. Submit Pull Requests

- Fix bugs
- Implement new features
- Improve documentation
- Add or improve tests
- Optimize performance

### 4. Contribute Detection Rules

- YARA rules for new malware families
- Behavioral patterns
- File format parsers

### 5. Contribute Machine Learning Models

- Pre-trained models for specific threat types
- Training datasets
- Model improvement suggestions

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, conda, etc.)

### Setup Steps

1. **Fork and Clone**

```bash
git clone https://github.com/YOUR_USERNAME/scanner-image-file-.git
cd scanner-image-file-/New\ folder
```

2. **Create Virtual Environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install Dependencies**

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

4. **Install Development Tools**

```bash
pip install pytest black flake8 mypy
```

5. **Run Tests**

```bash
pytest tests/
```

## Contributing YARA Rules

### Guidelines for YARA Rules

1. **File Structure**

```
data/yara_rules/
├── malware_family_name.yar
├── behavior_name.yar
└── file_format_name.yar
```

2. **Rule Template**

```yara
rule MalwareFamilyName_Behavior
{
    meta:
        author = "Your Name"
        description = "Detects [specific behavior or family]"
        date = "2025-11-25"
        reference = "https://example.com/analysis"
        severity = "high"  // high, medium, low
        
    strings:
        $string1 = "malicious_pattern" ascii wide
        $hex1 = { 4D 5A 90 00 }
        
    condition:
        uint16(0) == 0x5A4D and
        any of ($string*)
}
```

3. **Best Practices**

- Use descriptive rule names
- Include comprehensive metadata
- Test rules against benign files to avoid false positives
- Provide reference to malware analysis
- Document detection logic
- Use specific patterns, not generic ones

4. **Testing Your Rules**

```python
import yara

rules = yara.compile(filepath='your_rule.yar')
matches = rules.match('test_file.exe')
print(matches)
```

5. **Submission Process**

- Place rule file in `data/yara_rules/`
- Add test cases in `tests/test_yara_rules.py`
- Update `data/yara_rules/README.md` with rule description
- Submit pull request with "YARA Rule: [name]" title

## Contributing ML Models

### Model Guidelines

1. **Model Types Accepted**

- Image classification models (TensorFlow/Keras, PyTorch)
- Traditional ML models (scikit-learn)
- Behavioral analysis models
- Anomaly detection models

2. **Model Requirements**

```python
# Model metadata file (model_metadata.json)
{
    "name": "model_name",
    "version": "1.0.0",
    "framework": "tensorflow",  # or "sklearn", "pytorch"
    "architecture": "EfficientNetB0",
    "input_shape": [224, 224, 3],
    "classes": ["benign", "malicious"],
    "training_samples": 10000,
    "accuracy": 0.95,
    "precision": 0.93,
    "recall": 0.96,
    "f1_score": 0.94,
    "training_date": "2025-11-25",
    "author": "Your Name",
    "description": "Model for detecting..."
}
```

3. **Model Structure**

```
models/
├── model_name/
│   ├── model.h5  # or model.pkl
│   ├── model_metadata.json
│   ├── training_script.py
│   ├── evaluation_results.json
│   └── README.md
```

4. **Training Script Requirements**

```python
# training_script.py must include:
def train_model(data_dir, output_path, **kwargs):
    \"\"\"
    Train the model.
    
    Args:
        data_dir: Path to training data
        output_path: Path to save model
        **kwargs: Additional parameters
    
    Returns:
        Training history and metrics
    \"\"\"
    pass

def evaluate_model(model_path, test_data_dir):
    \"\"\"
    Evaluate model performance.
    
    Args:
        model_path: Path to model
        test_data_dir: Path to test data
    
    Returns:
        Evaluation metrics
    \"\"\"
    pass
```

5. **Model Size Limits**

- Models should be < 100MB when possible
- Large models should be hosted externally (provide download script)
- Include model quantization/compression if applicable

6. **Testing Your Model**

```bash
python train_model.py --data data/training --output models/my_model
python tests/test_model.py --model models/my_model
```

## Contributing Datasets

### Dataset Guidelines

1. **Dataset Types**

- Benign file samples
- Malware samples (hashes only, never actual malware)
- Training/validation/test splits

2. **Dataset Structure**

```
data/datasets/
├── dataset_name/
│   ├── benign/
│   │   └── samples/
│   ├── malicious/
│   │   └── hashes.txt  # SHA256 hashes only
│   ├── metadata.json
│   └── README.md
```

3. **Metadata Format**

```json
{
    "name": "Dataset Name",
    "version": "1.0.0",
    "date": "2025-11-25",
    "author": "Your Name",
    "description": "Dataset for...",
    "samples": {
        "benign": 5000,
        "malicious": 5000
    },
    "file_types": ["exe", "pdf", "docx"],
    "source": "Public threat intelligence feeds",
    "license": "MIT"
}
```

4. **Safety Requirements**

- **NEVER upload actual malware files**
- Use SHA256 hashes for malware references
- Include VirusTotal links for verification
- Document data sources
- Ensure compliance with data sharing agreements

## Code Style Guidelines

### Python Code Style

1. **Follow PEP 8**

```bash
flake8 your_file.py
black your_file.py  # Auto-format
```

2. **Type Hints**

```python
def function_name(param1: str, param2: int) -> Dict[str, Any]:
    \"\"\"
    Function description.
    
    Args:
        param1: Description
        param2: Description
    
    Returns:
        Description of return value
    \"\"\"
    return {}
```

3. **Documentation**

- Use Google-style docstrings
- Document all public methods and classes
- Include examples in docstrings

```python
class MyClass:
    \"\"\"
    Brief description.
    
    Longer description with usage details.
    
    Attributes:
        attribute1: Description
        attribute2: Description
    
    Example:
        >>> obj = MyClass()
        >>> result = obj.method()
    \"\"\"
    pass
```

4. **Naming Conventions**

- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

### Code Organization

```python
# 1. Standard library imports
import os
import sys

# 2. Third-party imports
import numpy as np
from fastapi import FastAPI

# 3. Local imports
from app.layer1_scanner import Layer1Scanner
```

## Testing Guidelines

### Writing Tests

1. **Test Structure**

```python
import pytest
from app.module_name import ClassName

class TestClassName:
    def setup_method(self):
        \"\"\"Setup before each test.\"\"\"
        self.obj = ClassName()
    
    def test_basic_functionality(self):
        \"\"\"Test basic functionality.\"\"\"
        result = self.obj.method()
        assert result == expected_value
    
    def test_edge_case(self):
        \"\"\"Test edge case.\"\"\"
        with pytest.raises(ValueError):
            self.obj.method(invalid_input)
```

2. **Test Coverage**

- Aim for > 80% code coverage
- Test all public methods
- Include edge cases and error conditions

```bash
pytest --cov=app tests/
```

3. **Test Files Location**

```
tests/
├── test_layer1_scanner.py
├── test_layer2_apsa.py
├── test_dl_classifier.py
├── test_api.py
└── fixtures/
    └── sample_files/
```

## Pull Request Process

### Before Submitting

1. **Update Your Fork**

```bash
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

2. **Make Changes**

- Write clean, documented code
- Add tests for new functionality
- Update documentation

3. **Run Tests**

```bash
pytest tests/
black app/ tests/
flake8 app/ tests/
```

4. **Commit Changes**

```bash
git add .
git commit -m "feat: Add [feature description]"
```

Use conventional commit messages:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `perf:` Performance improvement

### Submitting Pull Request

1. **Push to Fork**

```bash
git push origin feature/your-feature-name
```

2. **Create Pull Request**

- Go to GitHub repository
- Click "New Pull Request"
- Select your branch
- Fill out the PR template

3. **PR Template**

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
Describe testing performed

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings
```

4. **Review Process**

- Maintainers will review your PR
- Address feedback and comments
- Update PR as needed
- Once approved, PR will be merged

### After Merge

- Delete your feature branch
- Update your local repository
- Thank you for contributing!

## Questions?

If you have questions:

- Open a GitHub Issue
- Check existing documentation
- Review closed issues for similar questions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

**Thank you for contributing to making the internet safer!** 🛡️
