# image_analysis.py
# Functions for extracting features from the passkey image 

import numpy as np
from PIL import Image, ExifTags
import cv2
import hashlib
from io import BytesIO
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_image(path: str) -> Image.Image:
    """Load image, convert to RGB, and downsample to max 1080p if needed."""
    img = Image.open(path).convert('RGB')
    max_dim = 1080
    if img.width > max_dim or img.height > max_dim:
        # Downsample, preserving aspect ratio
        scale = min(max_dim / img.width, max_dim / img.height)
        new_size = (int(img.width * scale), int(img.height * scale))
        img = img.resize(new_size, Image.LANCZOS)
    return img


def get_raw_bytes(img: Image.Image) -> bytes:
    """Get canonical PNG bytes of the image."""
    with BytesIO() as output:
        img.save(output, format='PNG')
        return output.getvalue()


def compute_sha256(data: bytes) -> str:
    """Return hex digest of SHA-256 of data."""
    return hashlib.sha256(data).hexdigest()


def get_color_histogram(img: Image.Image) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    arr = np.array(img)
    hist_r, _ = np.histogram(arr[..., 0], bins=256, range=(0, 255))
    hist_g, _ = np.histogram(arr[..., 1], bins=256, range=(0, 255))
    hist_b, _ = np.histogram(arr[..., 2], bins=256, range=(0, 255))
    return hist_r, hist_g, hist_b


def get_average_rgb(img: Image.Image) -> Tuple[int, int, int]:
    arr = np.array(img)
    avg = arr.mean(axis=(0, 1))
    return tuple(int(x) for x in avg)


def get_entropy(img: Image.Image) -> float:
    arr = np.array(img.convert('L')).flatten()
    hist, _ = np.histogram(arr, bins=256, range=(0, 255))
    prob = hist / np.sum(hist)
    prob = prob[prob > 0]
    entropy = -np.sum(prob * np.log2(prob))
    return float(entropy)


def get_edge_map(img: Image.Image, downsample_size=(32, 32)) -> np.ndarray:
    gray = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2GRAY)
    edges = cv2.Canny(gray, threshold1=100, threshold2=200)
    small = cv2.resize(edges, downsample_size, interpolation=cv2.INTER_AREA)
    binarized = (small > 0).astype(np.uint8)
    return binarized.flatten()  # length = 1024


def extract_color_histogram(image: Image.Image):
    # Returns a 256-bin histogram for each channel (R, G, B)
    arr = np.array(image.convert('RGB'))
    hist_r, _ = np.histogram(arr[..., 0], bins=256, range=(0, 255))
    hist_g, _ = np.histogram(arr[..., 1], bins=256, range=(0, 255))
    hist_b, _ = np.histogram(arr[..., 2], bins=256, range=(0, 255))
    return hist_r, hist_g, hist_b


def extract_pixel_intensity(image: Image.Image):
    # Returns flattened 1D array of pixel intensities (grayscale)
    arr = np.array(image.convert('L'))
    return arr.flatten()


def extract_exif_metadata(image: Image.Image):
    # Returns EXIF metadata dict if available, else None
    try:
        exif = image._getexif()
        if exif:
            return {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    except Exception:
        pass
    return None


def extract_edge_map(image: Image.Image, size=(32, 32)):
    # Returns a downsampled edge map fingerprint
    arr = np.array(image.convert('L'))
    edges = cv2.Canny(arr, 100, 200)
    small = cv2.resize(edges, size, interpolation=cv2.INTER_AREA)
    return small


def compute_entropy(arr):
    # arr: 1D array of pixel intensities
    hist, _ = np.histogram(arr, bins=256, range=(0, 255))
    prob = hist / np.sum(hist)
    prob = prob[prob > 0]
    entropy = -np.sum(prob * np.log2(prob))
    return entropy


def extract_all_features(image_path):
    image = Image.open(image_path)
    hist_r, hist_g, hist_b = extract_color_histogram(image)
    pixel_intensity = extract_pixel_intensity(image)
    exif = extract_exif_metadata(image)
    edge_map = extract_edge_map(image)
    sha256 = compute_sha256(get_raw_bytes(image))
    avg_rgb = get_average_rgb(image)
    entropy = get_entropy(image)
    edge_map_flat = edge_map.flatten()
    return {
        'hist_r': hist_r,
        'hist_g': hist_g,
        'hist_b': hist_b,
        'pixel_intensity': pixel_intensity,
        'exif': exif,
        'edge_map': edge_map,
        'sha256': sha256,
        'avg_rgb': avg_rgb,
        'entropy': entropy,
        'edge_map_flat': edge_map_flat
    }


def derive_seed_from_hash(hash_hex: str) -> int:
    """
    Convert first 16 hex characters of SHA-256 to a 32-bit integer seed.
    """
    return int(hash_hex[:16], 16) % (2**32)


def derive_key_material(hash_hex: str, entropy: float) -> bytes:
    """
    Combine hash + scaled entropy, use HKDF to derive a 256-bit (32-byte) key.
    """
    hash_bytes = bytes.fromhex(hash_hex)
    salt = int(entropy * 1e6).to_bytes(8, 'big')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'CodeMorpherAI_Key',
    )
    return hkdf.derive(hash_bytes)


class ImageFingerprint:
    def __init__(self, path: str):
        self.img = load_image(path)
        self.raw_bytes = get_raw_bytes(self.img)
        self.sha256 = compute_sha256(self.raw_bytes)        # 64-hex chars
        self.r_hist, self.g_hist, self.b_hist = get_color_histogram(self.img)
        self.avg_r, self.avg_g, self.avg_b = get_average_rgb(self.img)
        self.entropy = get_entropy(self.img)
        self.edge_map = get_edge_map(self.img)              # 1024 bits
        self.seed = derive_seed_from_hash(self.sha256)
        self.aes_key = derive_key_material(self.sha256, self.entropy)

    @property
    def histograms(self):
        return (self.r_hist, self.g_hist, self.b_hist)

    @property
    def avg_rgb(self):
        return (self.avg_r, self.avg_g, self.avg_b)

# --- Suggestions for future extensibility ---
# - You could also use additional image features (e.g., avg_rgb, edge_map) as part of the salt or info for even more entropy.
# - For more advanced polymorphism, consider using a combination of multiple hashes (e.g., SHA-256 of histogram, edge-map, etc.)
# - For language-specific loaders, you may want to derive multiple keys (e.g., one for code, one for loader obfuscation). 