# encryptor_core.py
# Main logic for encrypting source code using image-derived algorithms 

import argparse
import base64
from engine import image_analysis
from engine import algo_generator
from pathlib import Path
import os
from typing import Tuple, Dict, Any
import zlib
import uuid
import platform
import subprocess
import sys
import string

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

LOADER_TEMPLATE_PATH = 'templates/loader_python.template'


def main():
    parser = argparse.ArgumentParser(description='CodeMorpherAI-X Encryptor (Python)')
    parser.add_argument('--input', required=True, help='Path to input source code')
    parser.add_argument('--image', required=True, help='Path to passkey image')
    parser.add_argument('--output', required=True, help='Path to output locked code')
    args = parser.parse_args()

    # Load code
    with open(args.input, 'rb') as f:
        code_bytes = f.read()

    # Extract image features
    features = image_analysis.extract_all_features(args.image)

    # Encrypt
    encrypted = algo_generator.layered_encrypt(code_bytes, features)
    b64_encrypted = base64.b64encode(encrypted).decode('utf-8')

    # Generate blueprint and obfuscate
    fingerprint = image_analysis.ImageFingerprint(args.image)
    blueprint = algo_generator.generate_blueprint(fingerprint)
    blueprint_obscured = algo_generator.obscure_blueprint(blueprint)
    # Escape curly braces for .format()
    blueprint_obscured_escaped = blueprint_obscured.replace('{', '{{').replace('}', '}}')
    timestamp_int = generate_timestamp_int(blueprint['metadata']['timestamp'])
    expected_env_fp = compute_env_fp(fingerprint.sha256)

    # Prepare loader
    with open(LOADER_TEMPLATE_PATH, 'r', encoding='utf-8') as f:
        loader_template = f.read()
    loader_template = loader_template.replace('{blueprint_obscured_str}', '$blueprint_obscured_str')\
                                     .replace('{timestamp_int}', '$timestamp_int')\
                                     .replace('{encrypted_payload_b64}', '$encrypted_payload_b64')\
                                     .replace('{expected_hash}', '$expected_hash')\
                                     .replace('{expected_env_fp}', '$expected_env_fp')\
                                     .replace('{compressed_loader_b64}', '$compressed_loader_b64')
    template = string.Template(loader_template)
    filled_loader = template.safe_substitute(
        blueprint_obscured_str=blueprint_obscured,
        timestamp_int=timestamp_int,
        encrypted_payload_b64=b64_encrypted,
        expected_hash="{expected_hash}",  # Placeholder for now
        expected_env_fp=expected_env_fp,
        compressed_loader_b64="COMPRESSED_PLACEHOLDER"
    )

    # Compress and encode the loader
    compressed_loader_b64 = compress_and_encode_loader(filled_loader)
    # Now fill the compressed_loader_b64 placeholder
    final_loader = filled_loader.replace('COMPRESSED_PLACEHOLDER', compressed_loader_b64)

    # Write output (with fixed hash placeholder)
    HASH_PLACEHOLDER = 'HASH_PLACEHOLDER_64CHARS______________________________________________'
    final_loader = final_loader.replace('{expected_hash}', HASH_PLACEHOLDER)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(final_loader)

    # Compute SHA-256 hash of the file with the placeholder
    with open(args.output, 'rb') as f:
        loader_bytes = f.read()
    # Replace the hash region with the placeholder for hashing
    loader_bytes_for_hash = loader_bytes.replace(HASH_PLACEHOLDER.encode('utf-8'), HASH_PLACEHOLDER.encode('utf-8'))
    import hashlib
    loader_hash = hashlib.sha256(loader_bytes_for_hash).hexdigest()

    # Insert the real hash
    final_loader_with_hash = final_loader.replace(HASH_PLACEHOLDER, loader_hash)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(final_loader_with_hash)

def load_source_file(path: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    Read the entire file as bytes and return with metadata (file extension).
    """
    raw_code = open(path, 'rb').read()
    file_extension = os.path.splitext(path)[1]
    metadata = {"file_extension": file_extension}
    return raw_code, metadata

def create_blueprint_for_image(image_path: str):
    """
    Create an EncryptionBlueprint and its obfuscated string from an image.
    """
    fingerprint = image_analysis.ImageFingerprint(image_path)
    blueprint = algo_generator.generate_blueprint(fingerprint)
    blueprint_obscured = algo_generator.obscure_blueprint(blueprint)
    return blueprint, blueprint_obscured

def apply_encryption_steps(payload: bytes, blueprint, fingerprint) -> bytes:
    """
    Apply each encryption step in the blueprint to the payload using the fingerprint.
    """
    data = payload
    for step in blueprint['steps']:
        primitive = step['primitive']
        params = step['parameters']
        if primitive == 'xor':
            seed_i = params['seed']
            data = algo_generator.xor_primitive(data, seed_i)
        elif primitive == 'substitute':
            sbox = algo_generator.generate_sbox(
                fingerprint.r_hist, fingerprint.g_hist, fingerprint.b_hist, params['seed']
            )
            data = algo_generator.substitute_bytes(data, sbox)
        elif primitive == 'permute':
            data = algo_generator.permute_bytes(data, fingerprint.edge_map, params['seed'])
        elif primitive == 'swap':
            data = algo_generator.swap_blocks(data, params['block_size'], params['seed'])
        elif primitive == 'aes':
            # Uncomment and implement if AES is enabled in blueprint
            # iv = bytes.fromhex(params['iv'])
            # key = fingerprint.aes_key
            # data = aes_encrypt(data, key, iv)
            raise NotImplementedError('AES primitive not implemented in Phase 1')
        else:
            raise ValueError(f"Unknown primitive: {primitive}")
    return data

def get_loader_template_path(file_extension: str) -> str:
    ext_map = {
        '.py': 'templates/loader_python.template',
        '.c': 'templates/loader_c.template',
        '.java': 'templates/loader_java.template',
        '.js': 'templates/loader_js.template',
    }
    return ext_map.get(file_extension, 'templates/loader_python.template')  # Default to Python

def fill_loader_template(template_str: str, blueprint_obscured: str, timestamp_int: int, encrypted_payload_b64: str) -> str:
    return template_str.replace('{blueprint_obscured_str}', blueprint_obscured)\
                       .replace('{timestamp_int}', str(timestamp_int))\
                       .replace('{encrypted_payload_b64}', encrypted_payload_b64)

def generate_timestamp_int(timestamp_iso: str) -> int:
    """
    Convert ISO timestamp to integer (e.g., 2025-06-06T14:00:00Z -> 20250606140000)
    Strips fractional seconds if present.
    """
    sanitized = timestamp_iso.replace('-', '').replace(':', '').replace('T','').replace('Z','')
    if '.' in sanitized:
        sanitized = sanitized.split('.')[0]
    return int(sanitized)

def compress_and_encode_loader(filled_loader_code: str) -> str:
    compressed = zlib.compress(filled_loader_code.encode('utf-8'))
    return base64.b64encode(compressed).decode('utf-8')

def get_bootstrap_loader(compressed_loader_b64: str) -> str:
    return (
        'import zlib, base64\n'
        'COMPRESSED_LOADER = """' + compressed_loader_b64 + '"""\n'
        'if __name__ == "__main__":\n'
        '    code = zlib.decompress(base64.b64decode(COMPRESSED_LOADER.encode(\'utf-8\'))).decode(\'utf-8\')\n'
        '    exec(code, globals(), locals())\n'
    )

def get_mac():
    return hex(uuid.getnode())[2:]

def get_cpu_id():
    if platform.system() == 'Windows':
        try:
            # Try to get CPU ID using wmic, but handle if wmic is missing
            import shutil
            if shutil.which('wmic') is None:
                return 'unknown'
            return subprocess.check_output('wmic cpu get ProcessorId', shell=True).decode().split('\n')[1].strip()
        except Exception:
            return 'unknown'
    elif platform.system() == 'Linux':
        try:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if 'Serial' in line or 'ID' in line:
                        return line.split(':')[1].strip()
        except Exception:
            return 'unknown'
    return 'unknown'

def compute_env_fp(image_sha256):
    mac = get_mac()
    cpu_id = get_cpu_id()
    concat = (mac + cpu_id + image_sha256).encode('utf-8')
    import hashlib
    return hashlib.sha256(concat).hexdigest()

def encrypt_and_package(source_path: str, image_path: str, output_path: str):
    import base64
    import os
    # 1. Load & fingerprint image
    fingerprint = image_analysis.ImageFingerprint(image_path)

    # 2. Load source code bytes
    raw_code, metadata = load_source_file(source_path)

    # 3. Generate Blueprint & Obscured Blueprint
    blueprint, blueprint_obscured = create_blueprint_for_image(image_path)

    # 4. Encrypt raw bytes
    encrypted_bytes = apply_encryption_steps(raw_code, blueprint, fingerprint)

    # 5. Base64-encode encrypted payload
    encrypted_payload_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    # 6. Choose loader template based on file extension
    ext = metadata['file_extension']  # e.g., ".py"
    if ext == ".py":
        template_path = os.path.join("templates", "loader_python.template")
    elif ext == ".c":
        template_path = os.path.join("templates", "loader_c.template")
    elif ext == ".java":
        template_path = os.path.join("templates", "loader_java.template")
    elif ext == ".js":
        template_path = os.path.join("templates", "loader_js.template")
    else:
        template_path = os.path.join("templates", "loader_python.template")  # Default

    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()

    # Compute environment fingerprint
    expected_env_fp = compute_env_fp(fingerprint.sha256)

    # 7. Fill placeholders
    filled_loader = template.format(
        blueprint_obscured_str=blueprint_obscured,
        timestamp_int=generate_timestamp_int(blueprint['metadata']['timestamp']),
        encrypted_payload_b64=encrypted_payload_b64,
        expected_hash="{expected_hash}",  # Placeholder, will be replaced below
        expected_env_fp=expected_env_fp
    )

    # Compute expected hash for integrity check
    import hashlib
    loader_with_placeholder = filled_loader.replace('{expected_hash}', 'PLACEHOLDER_HASH')
    expected_hash = hashlib.sha256(loader_with_placeholder.encode('utf-8')).hexdigest()
    filled_loader = filled_loader.replace('{expected_hash}', expected_hash)

    # Compress and encode the loader, then wrap in a bootstrap
    compressed_loader_b64 = compress_and_encode_loader(filled_loader)
    bootstrap_loader = get_bootstrap_loader(compressed_loader_b64)

    # 8. Save to output_path (same extension, or a custom extension if you prefer)
    with open(output_path, 'w', encoding='utf-8') as fout:
        fout.write(bootstrap_loader)

    print(f"[*] Encrypted file written to: {output_path}")

if __name__ == '__main__':
    main() 