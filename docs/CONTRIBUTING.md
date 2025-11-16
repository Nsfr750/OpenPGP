# Contributing to OpenPGP

Thank you for your interest in contributing to OpenPGP! We appreciate your time and effort in helping us improve this project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Requests](#pull-requests)
- [Reporting Issues](#reporting-issues)
- [Feature Requests](#feature-requests)
- [Code Style](#code-style)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

This project adheres to the Contributor Covenant [code of conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
   ```bash
   git clone https://github.com/Nsfr750/OpenPGP.git
   cd OpenPGP
   ```
3. Set up the development environment (see below)

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Making Changes

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/description-of-fix
   ```

2. Make your changes following the code style guide

3. Run tests:
   ```bash
   pytest
   ```

4. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add: New feature description"
   ```

## Pull Requests

1. Push your changes to your fork:
   ```bash
   git push origin your-branch-name
   ```

2. Open a Pull Request (PR) on GitHub
   - Reference any related issues
   - Provide a clear description of changes
   - Include screenshots if applicable

## Reporting Issues

When reporting issues, please include:
- A clear title and description
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Any relevant error messages or logs

## Feature Requests

For feature requests:
- Explain the problem you're trying to solve
- Describe the proposed solution
- Provide examples of similar implementations if available

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code
- Use type hints for better code clarity
- Write docstrings for all public functions and classes
- Keep lines under 88 characters (Black formatter default)

## Documentation

- Update relevant documentation when adding new features
- Follow the existing documentation style
- Include examples where helpful

## License

By contributing, you agree that your contributions will be licensed under the [GNU General Public License v3.0](../LICENSE).

---
*Thank you for contributing to OpenPGP!*
