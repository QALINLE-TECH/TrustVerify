import hashlib
import json
import os
import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------
# TASK 1: Hash a single file using SHA-256
# ---------------------------------------------
def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------
# TASK 2: Generate manifest (metadata.json)
# ---------------------------------------------
def generate_manifest(directory):
    EXCLUDE = {"metadata.json", "private_key.pem", "public_key.pem", "signature.sig"}
    manifest = {}
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath) and filename not in EXCLUDE:
            manifest[filename] = hash_file(filepath)

    manifest_path = os.path.join(directory, "metadata.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    print(f"[OK] Manifest created at: {manifest_path}")
    for name, h in manifest.items():
        print(f"  {name}: {h}")


# ---------------------------------------------
# TASK 3: Check files against manifest
# ---------------------------------------------
def check_integrity(directory):
    manifest_path = os.path.join(directory, "metadata.json")
    if not os.path.exists(manifest_path):
        print("[ERROR] metadata.json not found. Run --manifest first.")
        return

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    print("[*] Checking file integrity...")
    all_ok = True
    for filename, original_hash in manifest.items():
        filepath = os.path.join(directory, filename)
        if not os.path.exists(filepath):
            print(f"  [MISSING] {filename}")
            all_ok = False
        else:
            current_hash = hash_file(filepath)
            if current_hash == original_hash:
                print(f"  [OK] {filename}")
            else:
                print(f"  [TAMPERED] {filename}")
                all_ok = False

    if all_ok:
        print("\n[OK] All files are intact. No tampering detected.")
    else:
        print("\n[WARNING] Some files have been modified or are missing!")


# ---------------------------------------------
# TASK 4: Generate RSA key pair
# ---------------------------------------------
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[OK] Keys generated:")
    print("  private_key.pem  <- Keep this SECRET")
    print("  public_key.pem   <- Share this with the Receiver")


# ---------------------------------------------
# TASK 5: Sign the manifest
# ---------------------------------------------
def sign_manifest(manifest_path="metadata.json", private_key_path="private_key.pem"):
    if not os.path.exists(manifest_path):
        print("[ERROR] metadata.json not found. Run --manifest first.")
        return
    if not os.path.exists(private_key_path):
        print("[ERROR] private_key.pem not found. Run --keygen first.")
        return

    manifest_hash = hash_file(manifest_path).encode()

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    signature = private_key.sign(
        manifest_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)

    print("[OK] Manifest signed successfully!")
    print("  signature.sig <- Send this along with metadata.json and public_key.pem")


# ---------------------------------------------
# TASK 6: Verify the manifest signature
# ---------------------------------------------
def verify_manifest(manifest_path="metadata.json", signature_path="signature.sig", public_key_path="public_key.pem"):
    for path in [manifest_path, signature_path, public_key_path]:
        if not os.path.exists(path):
            print(f"[ERROR] File not found: {path}")
            return

    manifest_hash = hash_file(manifest_path).encode()

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            manifest_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("[OK] Verification SUCCESSFUL!")
        print("  The manifest is authentic and has NOT been tampered with.")
    except Exception:
        print("[FAILED] Verification FAILED!")
        print("  The manifest has been altered or the signature is invalid.")


# ---------------------------------------------
# CLI Entry Point
# ---------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="TrustVerify - File Integrity & Digital Signature CLI Tool"
    )

    parser.add_argument("--hash", metavar="FILE", help="Hash a single file (SHA-256)")
    parser.add_argument("--manifest", metavar="DIR", help="Generate metadata.json for a directory")
    parser.add_argument("--check", metavar="DIR", help="Check file integrity against metadata.json")
    parser.add_argument("--keygen", action="store_true", help="Generate RSA public/private key pair")
    parser.add_argument("--sign", action="store_true", help="Sign metadata.json with private key")
    parser.add_argument("--verify", action="store_true", help="Verify metadata.json signature")

    args = parser.parse_args()

    if args.hash:
        if os.path.exists(args.hash):
            print(f"[OK] SHA-256 of '{args.hash}':\n  {hash_file(args.hash)}")
        else:
            print(f"[ERROR] File not found: {args.hash}")
    elif args.manifest:
        generate_manifest(args.manifest)
    elif args.check:
        check_integrity(args.check)
    elif args.keygen:
        generate_keys()
    elif args.sign:
        sign_manifest()
    elif args.verify:
        verify_manifest()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
