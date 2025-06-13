# algo_generator.py
# Functions for generating encryption algorithms based on image features 

import numpy as np
import random
import hashlib
from typing import List, Dict, Any, TypedDict, Tuple
from math import ceil
from datetime import datetime
import json
import base64
# Optional: from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Optional: from cryptography.hazmat.backends import default_backend
from engine.image_analysis import derive_seed_from_hash

def generate_sbox(seed_bytes):
    # Generate a 256-entry S-Box using a PRNG seeded by seed_bytes
    sbox = list(range(256))
    rng = random.Random(seed_bytes)
    rng.shuffle(sbox)
    return np.array(sbox, dtype=np.uint8)

def chaotic_xor_chain(data, seed_bytes):
    # XOR each byte with a PRNG stream seeded by seed_bytes
    rng = random.Random(seed_bytes)
    prng_stream = [rng.randrange(256) for _ in range(len(data))]
    return bytes([b ^ p for b, p in zip(data, prng_stream)])

def byte_permutation(data, edge_map_flat):
    indices = np.argsort(edge_map_flat)
    if len(indices) > len(data):
        indices = indices[:len(data)]
    elif len(indices) < len(data):
        indices = np.pad(indices, (0, len(data)-len(indices)), 'wrap')
    # Ensure all indices are within bounds
    indices = np.array(indices) % len(data)
    return bytes([data[i] for i in indices])

def block_swapping(data, block_size, seed_bytes):
    # Split data into blocks and swap blocks based on PRNG
    n_blocks = len(data) // block_size
    blocks = [data[i*block_size:(i+1)*block_size] for i in range(n_blocks)]
    if len(data) % block_size:
        blocks.append(data[n_blocks*block_size:])
    rng = random.Random(seed_bytes)
    rng.shuffle(blocks)
    return b''.join(blocks)

def layered_encrypt(data, features):
    # Apply XOR -> S-Box -> permutation -> block swap
    seed = derive_seed_from_hash(features['sha256'])
    sbox = generate_sbox(features['hist_r'], features['hist_g'], features['hist_b'], seed)
    data = chaotic_xor_chain(data, features['sha256'])
    data = bytes([sbox[b] for b in data])
    data = byte_permutation(data, features['edge_map_flat'])
    block_size = max(16, int(features['avg_rgb'][0]) % 64)
    data = block_swapping(data, block_size, features['sha256'])
    return data

def layered_decrypt(data, features):
    # Reverse block swap -> reverse permutation -> reverse S-Box -> reverse XOR
    seed = derive_seed_from_hash(features['sha256'])
    sbox = generate_sbox(features['hist_r'], features['hist_g'], features['hist_b'], seed)
    block_size = max(16, int(features['avg_rgb'][0]) % 64)
    # Reverse block swap
    n_blocks = len(data) // block_size
    blocks = [data[i*block_size:(i+1)*block_size] for i in range(n_blocks)]
    if len(data) % block_size:
        blocks.append(data[n_blocks*block_size:])
    rng = random.Random(features['sha256'])
    order = list(range(len(blocks)))
    rng.shuffle(order)
    # Inverse permutation
    inv_order = np.argsort(order)
    blocks = [blocks[i] for i in inv_order]
    data = b''.join(blocks)
    # Reverse byte permutation
    indices = np.argsort(features['edge_map_flat'])
    if len(indices) > len(data):
        indices = indices[:len(data)]
    elif len(indices) < len(data):
        indices = np.pad(indices, (0, len(data)-len(indices)), 'wrap')
    inv_indices = np.argsort(indices)
    data = bytes([data[i] for i in inv_indices])
    # Reverse S-Box
    inv_sbox = np.argsort(sbox)
    data = bytes([inv_sbox[b] for b in data])
    # Reverse XOR
    rng = random.Random(features['sha256'])
    prng_stream = [rng.randrange(256) for _ in range(len(data))]
    data = bytes([b ^ p for b, p in zip(data, prng_stream)])
    return data 

# XOR Primitive

def xor_primitive(data: bytes, seed: int) -> bytes:
    """
    XOR each byte of data with a PRNG stream seeded by seed.
    """
    rng = random.Random(seed)
    prng_stream = [rng.randrange(256) for _ in range(len(data))]
    return bytes([b ^ p for b, p in zip(data, prng_stream)])

# Substitution Primitive (S-Box)

def generate_sbox(hist_r: np.ndarray, hist_g: np.ndarray, hist_b: np.ndarray, seed: int) -> List[int]:
    """
    Generate a 256-entry S-Box by merging and sorting histograms, then shuffling with seed.
    """
    merged = np.empty(768, dtype=int)
    merged[0::3] = hist_r
    merged[1::3] = hist_g
    merged[2::3] = hist_b
    # Sort merged histogram to get ranking
    ranking = np.argsort(-merged)  # Descending
    base_sbox = list(range(256))
    rng = random.Random(seed)
    rng.shuffle(base_sbox)
    return base_sbox

def substitute_bytes(data: bytes, sbox: List[int]) -> bytes:
    """
    Substitute each byte using the S-Box.
    """
    return bytes([sbox[b] for b in data])

# Permutation Primitive

def permute_bytes(data: bytes, edge_map: np.ndarray, seed: int) -> bytes:
    """
    Permute bytes using edge_map as a pseudo-random ordering, finalized by seed.
    """
    # Convert 1024 bits to 512 bytes
    edge_bytes = np.packbits(edge_map).astype(np.uint8)
    # Sort edge_bytes descending to get permutation indices
    indices = np.argsort(-edge_bytes)
    # Finalize permutation with seed
    rng = random.Random(seed)
    indices = list(indices)
    rng.shuffle(indices)
    # Pad or truncate indices to match data length
    if len(indices) > len(data):
        indices = indices[:len(data)]
    elif len(indices) < len(data):
        indices = indices + list(range(len(indices), len(data)))
    return bytes([data[i] for i in indices])

# Block Swap Primitive

def swap_blocks(data: bytes, block_size: int, seed: int) -> bytes:
    """
    Split data into blocks and swap them using a PRNG seeded by seed.
    """
    n_blocks = ceil(len(data) / block_size)
    blocks = [data[i*block_size:(i+1)*block_size] for i in range(n_blocks)]
    rng = random.Random(seed)
    order = list(range(n_blocks))
    rng.shuffle(order)
    swapped = [blocks[i] for i in order]
    return b''.join(swapped)

# Optional: AES Primitive (not used in Phase 1)
# def aes_encrypt(data: bytes, aes_key: bytes, seed: int) -> bytes:
#     """
#     Encrypt data with AES-CBC using a random IV derived from seed.
#     """
#     rng = random.Random(seed)
#     iv = bytes([rng.randrange(256) for _ in range(16)])
#     cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
#     encryptor = cipher.encryptor()
#     # Pad data to 16 bytes
#     pad_len = 16 - (len(data) % 16)
#     padded = data + bytes([pad_len] * pad_len)
#     ct = encryptor.update(padded) + encryptor.finalize()
#     return iv + ct 

class EncryptionStep(TypedDict):
    primitive: str
    parameters: Dict[str, Any]

class EncryptionBlueprint(TypedDict):
    steps: List[EncryptionStep]
    metadata: Dict[str, Any]

def select_complexity_tier(img) -> str:
    width, height = img.size
    if width <= 320 and height <= 240:
        return "low"
    elif width <= 1280 and height <= 720:
        return "medium"
    else:
        return "high"

def inject_noise(data: bytes, seed: int) -> Tuple[bytes, str]:
    """
    Injects random noise (1-32 bytes) as prefix or suffix, returns (noisy_data, position).
    """
    prng = random.Random(seed)
    noise_len = prng.randrange(1, 33)  # 1 to 32 random bytes
    noise = bytes(prng.randrange(0,256) for _ in range(noise_len))
    if prng.random() < 0.5:
        return noise + data, "prefix"
    else:
        return data + noise, "suffix"

def generate_blueprint(fingerprint) -> EncryptionBlueprint:
    tier = select_complexity_tier(fingerprint.img)
    entropy = fingerprint.entropy
    rng = random.Random(fingerprint.seed)
    if tier == "low":
        primitives = ["xor", "substitute", "permute"]
        N = rng.randint(3, 4)
    elif tier == "medium":
        primitives = ["xor", "substitute", "permute", "swap", "aes"]
        N = rng.randint(4, 6)
    else:  # high
        primitives = ["xor", "substitute", "permute", "swap", "aes"]
        N = rng.randint(6, 8)
    steps = []
    aes_inserted = 0
    aes_round = 1
    for i in range(N):
        # For high tier, randomly inject noise layers
        if tier == "high" and rng.random() < 0.25:
            noise_seed = (fingerprint.seed ^ i) ^ int(hashlib.sha256(b'noise_inject').hexdigest()[:8], 16)
            # Determine position for blueprint
            _, position = inject_noise(b'', noise_seed)
            steps.append({"primitive": "noise_inject", "parameters": {"seed": noise_seed, "position": position}})
        if tier == "medium" and aes_inserted < 1 and rng.random() < 0.3:
            primitive = "aes"
            aes_inserted += 1
        elif tier == "high" and aes_inserted < 2 and (i == 1 or i == N-2):
            primitive = "aes"
            aes_inserted += 1
        else:
            primitive = rng.choice([p for p in primitives if p != "aes"] if (tier == "low" or aes_inserted >= (1 if tier == "medium" else 2)) else primitives)
        step_name_hash = int(hashlib.sha256(primitive.encode()).hexdigest()[:8], 16)
        seed_i = (fingerprint.seed ^ i) ^ step_name_hash
        params = {"seed": seed_i}
        if primitive == "swap":
            if tier == "medium":
                block_size = int((entropy * 50) % 512 + 64)
            else:
                block_size = int((entropy * 100) % 2048 + 128)
            params["block_size"] = block_size
        elif primitive == "aes":
            hmac = hashlib.pbkdf2_hmac('sha256', fingerprint.sha256.encode(), str(i).encode(), 1000)
            iv = hmac[:16].hex()
            params["iv_hex"] = iv
            params["aes_round"] = aes_round
            aes_round += 1
            params["aes_key"] = fingerprint.aes_key.hex()
        elif primitive == "substitute":
            params["hist_r"] = fingerprint.r_hist.tolist()
            params["hist_g"] = fingerprint.g_hist.tolist()
            params["hist_b"] = fingerprint.b_hist.tolist()
        elif primitive == "permute":
            params["edge_map"] = fingerprint.edge_map.tolist()
        steps.append({"primitive": primitive, "parameters": params})
    metadata = {
        "version": 1,
        "image_sha256": fingerprint.sha256,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "tier": tier,
    }
    return {"steps": steps, "metadata": metadata}

def obscure_blueprint(blueprint: EncryptionBlueprint) -> str:
    """
    Serialize blueprint to JSON, XOR with PRNG stream seeded from timestamp, then Base64-encode.
    """
    raw = json.dumps(blueprint).encode('utf-8')
    # Seed PRNG from timestamp (remove non-digits for int)
    ts = blueprint['metadata']['timestamp']
    ts_seed = int(''.join(filter(str.isdigit, ts)))
    prng = random.Random(ts_seed)
    xored = bytes(b ^ prng.randrange(0, 256) for b in raw)
    return base64.b64encode(xored).decode('utf-8') 