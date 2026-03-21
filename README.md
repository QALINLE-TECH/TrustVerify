TrustVerify 🔐

A Python-based Command Line Interface (CLI) tool for file integrity verification and digital signatures using SHA-256 hashing and RSA encryption.

Features



SHA-256 Hashing – Generate a unique fingerprint for any file

Manifest Generator – Scan a directory and record all file hashes in metadata.json

Integrity Check – Detect unauthorized modifications (data tampering)

RSA Key Generation – Generate a public/private key pair

Digital Signing – Sign the manifest using a private key

Signature Verification – Verify the manifest authenticity using a public key



Requirements



Python 3.7+

cryptography library



Installation

bashpip install cryptography

Usage

Hash a single file

bashpython trustverify.py --hash filename.txt

Generate manifest for a directory

bashpython trustverify.py --manifest .

Check files for tampering

bashpython trustverify.py --check .

Generate RSA key pair

bashpython trustverify.py --keygen

Sign the manifest

bashpython trustverify.py --sign

Verify the manifest signature

bashpython trustverify.py --verify

Demo Workflow

bash# Step 1 - Hash a file

python trustverify.py --hash testfile.txt



\# Step 2 - Generate manifest

python trustverify.py --manifest .



\# Step 3 - Check integrity (all OK)

python trustverify.py --check .



\# Step 4 - Generate keys

python trustverify.py --keygen



\# Step 5 - Sign the manifest

python trustverify.py --sign



\# Step 6 - Verify signature

python trustverify.py --verify



\# Step 7 - Tamper with a file

echo hacked >> testfile.txt



\# Step 8 - Check again (TAMPERED detected!)

python trustverify.py --check .

Libraries Used



hashlib – Built-in Python library for SHA-256 hashing

cryptography – For RSA key generation, signing, and verification

json – For saving and reading the manifest file

argparse – For building the CLI interface



Project Structure

TrustVerify/

├── trustverify.py      # Main CLI tool

├── testfile.txt        # Sample file for testing

├── metadata.json       # Generated manifest (after running --manifest)

├── private\_key.pem     # Private key (after running --keygen)

├── public\_key.pem      # Public key (after running --keygen)

└── signature.sig       # Digital signature (after running --sign)

Authors

QALINLE-TECH Team

