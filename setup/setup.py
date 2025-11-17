#!/usr/bin/env python3
# setup/setup.py
from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README.md
readme_path = Path(__file__).parent.parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="openpgp",
    version="2.2.0",
    packages=find_packages(exclude=["tests*", "docs*", "setup*"]),
    python_requires=">=3.9",
    install_requires=[
        # Core Dependencies
        "PySide6>=6.9.1",
        "PySide6-Addons>=6.9.1",
        "PySide6-Essentials>=6.9.1",
        "shiboken6>=6.9.1",
        "dnspython>=2.5.0",
        "msgpack>=1.0.5",
        
        # FastAPI Dependencies
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "pydantic>=1.8.0",
        "python-jose[cryptography]>=3.3.0",
        "python-multipart>=0.0.5",
        "httpx>=0.19.0",
        "python-dotenv>=0.19.0",
        "pydantic-settings>=2.0.0",
        "aiohttp>=3.8.0",
        "email-validator>=2.0.0",
        
        # SCIM and SIEM Dependencies
        "scim2-filter-parser>=0.4.1",
        "scim2-tester>=0.2.4",  # Downgraded from 0.3.0 as it doesn't exist
        "scim2-cli>=0.2.3",
        "scim2-models>=0.1.0",
        # Removed package not available on PyPI 
        # "scim2-filter-grammar>=0.1.0",
        # "scim2-schema-validator>=0.1.0",

        # Cryptography
        "pgpy>=0.5.3",
        "cryptography>=42.0.0",
        "pyOpenSSL>=24.0.0",
        "python-gnupg>=0.5.1",
        "pycryptodome>=3.20.0",
        "argon2-cffi>=23.1.0",
        "liboqs-python>=0.8.0",    # For post-quantum cryptography
        "pqcrypto>=0.3.4,<1.0.0",  # Updated version constraint

        # QR Code and OTP
        "qrcode>=8.2",
        "pyotp>=2.9.0",
        "pyqrcode>=1.2.1",
    ],
    extras_require={
        "tpm": [
            "tpm2-pytss>=2.3.0; platform_system != 'Windows'",
            "wmi>=1.5.1; platform_system == 'Windows'",
            "pywin32>=311; platform_system == 'Windows'",
        ],
        "homomorphic": [
            "tenseal>=0.3.0",
            "numpy>=1.21.0",
        ],
        "dev": [
            "black>=24.3.0",
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "mypy>=1.5.0",
            "flake8>=6.1.0",
            "isort>=5.12.0",
            "pre-commit>=3.3.3",
        ],
        "postquantum": [
            "liboqs-python>=0.8.0",
            "pqcrypto>=0.3.4,<1.0.0",  # Updated version constraint
            "cryptography>=42.0.0",    # Ensure compatibility with post-quantum algorithms
        ],
    },
    entry_points={
        "console_scripts": [
            "openpgp=main:main",
        ],
    },
    # Metadata
    author="Nsfr750",
    author_email="nsfr750@yandex.com",
    description="A interface for OpenPGP with enhanced encryption, key management, and security features.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GPL-3.0-or-later",
    url="https://github.com/Nsfr750/OpenPGP",
    project_urls={
        "Bug Tracker": "https://github.com/Nsfr750/OpenPGP/issues",
        "Documentation": "https://github.com/Nsfr750/OpenPGP#readme",
        "Source Code": "https://github.com/Nsfr750/OpenPGP",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Security",
    ],
    keywords="pgp encryption security cryptography openpgp",
    package_data={
        "openpgp": [
            "assets/*",
            "lang/*",
            "*.md",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)