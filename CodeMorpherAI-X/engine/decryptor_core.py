# decryptor_core.py
# Main logic for decrypting and restoring the original source code 

import argparse
import base64
import re
import os
from engine import image_analysis
from engine import algo_generator
from pathlib import Path
from typing import Tuple
import json
import random

def extract_payload_from_loader(loader_path):
    # Extracts the base64 payload from the loader file
    with open(loader_path, 'r', encoding='utf-8') as f:
        code = f.read()
    match = re.search(r'ENCRYPTED_PAYLOAD = "([A-Za-z0-9+/=]+)"', code)
    if not match:
        raise ValueError('Encrypted payload not found in loader.')
    return match.group(1)

def detect_language_and_extract_components(locked_path: str) -> Tuple[str, str, str, int]:
    """
    Open locked_path as text. Detect file extension, extract OBSCURED_BP, ENCRYPTED_PAYLOAD, and timestamp_int.
    Return (extension, obscured_blueprint_str, encrypted_payload_b64, timestamp_int)
    """
    with open(locked_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # Detect extension
    extension = os.path.splitext(locked_path)[1]
    # Extract OBSCURED_BP
    pattern_bp = r'OBSCURED_BP\s*=\s*"([^"]+)"'
    match_bp = re.search(pattern_bp, content)
    if not match_bp:
        raise ValueError('OBSCURED_BP not found in locked file.')
    obscured_blueprint_str = match_bp.group(1)
    # Extract ENCRYPTED_PAYLOAD
    pattern_payload = r'ENCRYPTED_PAYLOAD\s*=\s*"([^"]+)"'
    match_payload = re.search(pattern_payload, content)
    if not match_payload:
        raise ValueError('ENCRYPTED_PAYLOAD not found in locked file.')
    encrypted_payload_b64 = match_payload.group(1)
    # Extract timestamp_int
    pattern_ts = r'salt_int\s*=\s*(\d+)'
    match_ts = re.search(pattern_ts, content)
    if not match_ts:
        raise ValueError('timestamp_int (salt_int) not found in locked file.')
    timestamp_int = int(match_ts.group(1))
    return extension, obscured_blueprint_str, encrypted_payload_b64, timestamp_int

def reconstruct_blueprint(obscured_str: str, timestamp_int: int):
    """
    Reverse Base64+XOR as in loader to recover the blueprint dict.
    """
    data = base64.b64decode(obscured_str.encode('utf-8'))
    prng = random.Random(timestamp_int)
    unxored = bytes(b ^ prng.randrange(0,256) for b in data)
    return json.loads(unxored.decode('utf-8'))

def invert_sbox(sbox):
    inv = [0]*256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

def generate_sbox_from_params(params):
    import numpy as np
    r = np.array(params['hist_r'])
    g = np.array(params['hist_g'])
    b = np.array(params['hist_b'])
    seed = params['seed']
    from engine.algo_generator import generate_sbox
    return generate_sbox(r, g, b, seed)

# Stubs for permutation/block helpers (to be implemented as needed)
def reconstruct_permutation(params):
    # For now, just return a range (identity); implement as needed
    return list(range(params.get('length', 0)))
def invert_permutation(order):
    inv = [0]*len(order)
    for i, v in enumerate(order):
        inv[v] = i
    return inv
def apply_permutation(data, inv_order):
    return bytes([data[i] for i in inv_order])
def reconstruct_block_order(params):
    # For now, just return a range (identity); implement as needed
    n_blocks = params.get('n_blocks', 1)
    return list(range(n_blocks))
def invert_block_order(order):
    inv = [0]*len(order)
    for i, v in enumerate(order):
        inv[v] = i
    return inv
def merge_blocks(data, inv_order):
    # For now, just return data; implement as needed
    return data

def decrypt_payload_with_blueprint(encrypted_payload_b64: str, blueprint) -> bytes:
    import base64
    import random
    data = base64.b64decode(encrypted_payload_b64.encode('utf-8'))
    steps = blueprint['steps'][::-1]
    for step in steps:
        prim = step['primitive']
        params = step['parameters']
        if prim == 'xor':
            prng = random.Random(params['seed'])
            data = bytes(b ^ prng.randrange(0,256) for b in data)
        elif prim == 'substitute':
            sbox = generate_sbox_from_params(params)
            inv_sbox = invert_sbox(sbox)
            data = bytes(inv_sbox[b] for b in data)
        elif prim == 'permute':
            order = reconstruct_permutation(params)
            inv_order = invert_permutation(order)
            data = apply_permutation(data, inv_order)
        elif prim == 'swap':
            order = reconstruct_block_order(params)
            inv_order = invert_block_order(order)
            data = merge_blocks(data, inv_order)
        elif prim == 'aes':
            # AES decryption not implemented in Phase 1
            raise NotImplementedError('AES decryption not implemented in Phase 1')
        else:
            raise ValueError(f"Unknown primitive: {prim}")
    return data  # Original source bytes

def viewer_cli(locked_path: str, image_path: str, output_path: str):
    # 1. Load image fingerprint to verify & possibly re-generate blueprint
    fp = image_analysis.ImageFingerprint(image_path)
    # 2. Extract components from locked file
    ext, obscured_bp_str, encrypted_payload_b64, timestamp_int = detect_language_and_extract_components(locked_path)
    # 3. Reconstruct blueprint
    blueprint = reconstruct_blueprint(obscured_bp_str, timestamp_int)
    # 4. Verify blueprint metadata['image_sha256'] == fp.sha256
    if blueprint['metadata']['image_sha256'] != fp.sha256:
        raise ValueError("Image does not match encryption!")
    # 5. Decrypt payload
    source_bytes = decrypt_payload_with_blueprint(encrypted_payload_b64, blueprint)
    # 6. Write to output_path (use same extension as locked file)
    with open(output_path, 'wb') as f:
        f.write(source_bytes)
    print(f"[+] Decrypted source written to: {output_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CodeMorpherAI Viewer/Decryptor")
    parser.add_argument("locked_file", help="Path to locked/ encrypted code file")
    parser.add_argument("image_key", help="Path to the exact passkey image")
    parser.add_argument("--out", default="output/decrypted_source.xxx", help="Where to write decrypted code")
    args = parser.parse_args()
    viewer_cli(args.locked_file, args.image_key, args.out) 