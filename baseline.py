import hashlib
import json
import os

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_baseline(file_list, output_file):
    """Creates a baseline of file hashes."""
    baseline = {}
    for file_path in file_list:
        if os.path.exists(file_path):
            try:
                file_hash = calculate_sha256(file_path)
                baseline[file_path] = file_hash
                print(f"Hashed {file_path}")
            except Exception as e:
                print(f"Error accessing {file_path}: {e}")
    
    with open(output_file, 'w') as f:
        json.dump(baseline, f, indent=4)
    print(f"\nBaseline created and saved to {output_file}")

if __name__ == "__main__":
    # List of critical files to monitor
    critical_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/boot/vmlinuz",  # Linux kernel
    ]
    create_baseline(critical_files, "file_hashes.json")
