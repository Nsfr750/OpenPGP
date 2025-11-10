from setuptools import setup, find_packages

setup(
    name="openpgp",
    version="2.1.0",
    packages=find_packages(),
    install_requires=[
        'PySide6>=6.4.0',
        'pyotp>=2.6.0',
        'argon2-cffi>=21.3.0',
        'cryptography>=36.0.0',
        'qrcode>=7.3.1',
        'requests>=2.28.0',
        'web3>=5.31.0',
    ],
    python_requires='>=3.8',
    author="Nsfr750",
    author_email="nsfr750@yandex.com",
    description="OpenPGP - A secure file encryption and sharing application",
    license="GPLv3",
    url="https://github.com/Nsfr750/OpenPGP",
)
