#!/usr/bin/env python3
# setup/comp.py
import os
import sys
import shutil
import platform
import subprocess
from pathlib import Path

# Project information
APP_NAME = "ZipPw"
VERSION = "1.0.0"
AUTHOR = "Nsfr750"
DESCRIPTION = "Un'applicazione per trovare password di file ZIP protetti utilizzando wordlist."
ENTRY_POINT = "main.py"

# Directories
BASE_DIR = Path(__file__).parent.parent
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"
SPEC_DIR = BASE_DIR / "spec"

# Nuitka options
NUITKA_OPTIONS = [
    "--mingw64",  # Use MinGW64 for compilation
    "--standalone",  # Create a standalone distribution
    "--onefile",  # Create a single executable file
    f"--output-filename={APP_NAME}",  # Output filename
    f"--output-dir={DIST_DIR}",  # Output directory
    f"--windows-icon-from-ico={BASE_DIR}/assets/icon.ico",  # Application icon
    "--windows-console-mode=disable",  # Disable console window for GUI apps
    "--enable-plugin=pyqt6",  # Enable PyQt6 plugin
    "--include-package=utils",  # Include utils package
    "--include-package=UI",  # Include UI package
    "--include-data-dir=assets=assets",  # Include assets directory
    f"--company-name={AUTHOR}",  # Company name
    f"--file-version={VERSION}",  # File version
    f"--product-version={VERSION}",  # Product version
    f"--file-description={DESCRIPTION}",  # File description
    f"--product-name={APP_NAME}",  # Product name
    f"--copyright=© 2024-2025 {AUTHOR} - All Rights Reserved",  # Copyright notice
]

def clean_build():
    """Clean up build and dist directories."""
    print("Cleaning build directories...")
    for directory in [DIST_DIR, BUILD_DIR, SPEC_DIR]:
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True, exist_ok=True)

def run_nuitka():
    """Run Nuitka to compile the application."""
    print(f"Compiling {APP_NAME} with Nuitka...")
    
    cmd = [
        sys.executable,
        "-m", "nuitka",
        *NUITKA_OPTIONS,
        str(BASE_DIR / ENTRY_POINT)
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"\nSuccessfully compiled {APP_NAME}!")
        print(f"Executable location: {DIST_DIR / f'{APP_NAME}.exe'}")
    except subprocess.CalledProcessError as e:
        print(f"Error during compilation: {e}", file=sys.stderr)
        sys.exit(1)

def sign_executable():
    """Sign the compiled executable."""
    executable = DIST_DIR / f"{APP_NAME}.exe"
    if not executable.exists():
        print("Executable not found for signing.", file=sys.stderr)
        return

    print("\nSigning the executable...")
    sign_script = BASE_DIR / "setup" / "firma.bat"
    if sign_script.exists():
        try:
            subprocess.run(str(sign_script), shell=True, check=True)
            print("Executable signed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"Error during signing: {e}", file=sys.stderr)
    else:
        print("Signing script not found. Skipping signing.", file=sys.stderr)

def main():
    """Main function to handle the build process."""
    print(f"Building {APP_NAME} v{VERSION}")
    print("=" * 50)
    
    # Check if Nuitka is installed
    try:
        import nuitka
    except ImportError:
        print("Nuitka is not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "nuitka"])
    
    clean_build()
    run_nuitka()
    sign_executable()
    
    print("\nBuild process completed!")

if __name__ == "__main__":
    main()