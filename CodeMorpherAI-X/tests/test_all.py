import subprocess
import os
import hashlib
import shutil
import time
import base64
import re
import math
import collections
from pathlib import Path
import pytest

def compute_entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

# Absolute project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENGINE_DIR = PROJECT_ROOT / "engine"
IMAGEKEYS_DIR = PROJECT_ROOT / "imagekeys"

# Check all required directories and files
required_dirs = [ENGINE_DIR, IMAGEKEYS_DIR]
for d in required_dirs:
    assert d.exists(), f"Required directory missing: {d}"

required_files = [
    ENGINE_DIR / "encryptor_core.py",
    ENGINE_DIR / "decryptor_core.py",
    IMAGEKEYS_DIR / "high_res_sample.jpg",
    IMAGEKEYS_DIR / "medium_res.jpg",
    IMAGEKEYS_DIR / "low_res.jpg",
]
for f in required_files:
    assert f.exists(), f"Required file missing: {f}"

@pytest.mark.parametrize("img_name, tier, min_entropy", [
    ("high_res_sample.jpg", "high", 7.9),
    ("medium_res.jpg", "medium", 7.5),
    ("low_res.jpg", "low", 7.0),
])
def test_python_e2e(tmp_path, img_name, tier, min_entropy):
    code = f'print("Hello, CodeMorpher! {tier}")\n'
    src_file = tmp_path / "hello.py"
    src_file.write_text(code, encoding='utf-8')

    img_src = IMAGEKEYS_DIR / img_name
    img_dest = tmp_path / "key.jpg"
    assert img_src.exists(), f"Image file not found: {img_src}"
    shutil.copy(img_src, img_dest)

    locked_file = tmp_path / "locked_hello.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    subprocess.run([
        "python", "-m", "engine.encryptor_core",
        "--input", str(src_file), "--image", str(img_dest), "--output", str(locked_file)
    ], check=True, cwd=PROJECT_ROOT, env=env)

    run = subprocess.run(["python", str(locked_file)], capture_output=True, text=True, cwd=tmp_path, env=env)
    assert f"Hello, CodeMorpher! {tier}" in run.stdout

    decrypted = tmp_path / "dec_hello.py"
    subprocess.run([
        "python", str(ENGINE_DIR / "decryptor_core.py"),
        str(locked_file), str(img_dest),
        "--out", str(decrypted)
    ], check=True, cwd=PROJECT_ROOT, env=env)

    dec_text = decrypted.read_text(encoding='utf-8')
    assert dec_text == code

    locked_text = locked_file.read_text(encoding='utf-8')
    m = re.search(r'ENCRYPTED_PAYLOAD = "([^"]+)"', locked_text)
    assert m, "Encrypted payload not found"
    data = base64.b64decode(m.group(1))
    ent = compute_entropy(data)
    assert ent >= min_entropy

def test_variance(tmp_path):
    src_file = tmp_path / "hello.py"
    src_file.write_text('print("Viva la encryption")\n', 'utf-8')
    img_src = IMAGEKEYS_DIR / "high_res_sample.jpg"
    img_dest = tmp_path / "key.jpg"
    assert img_src.exists(), f"Image file not found: {img_src}"
    shutil.copy(img_src, img_dest)

    locked1 = tmp_path / "locked1.py"
    locked2 = tmp_path / "locked2.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    subprocess.run([
        "python", "-m", "engine.encryptor_core", "--input", str(src_file), "--image", str(img_dest), "--output", str(locked1)
    ], check=True, cwd=PROJECT_ROOT, env=env)
    time.sleep(1)
    subprocess.run([
        "python", "-m", "engine.encryptor_core", "--input", str(src_file), "--image", str(img_dest), "--output", str(locked2)
    ], check=True, cwd=PROJECT_ROOT, env=env)
    assert locked1.read_bytes() != locked2.read_bytes()

def test_entropy(tmp_path):
    src_file = tmp_path / "medium.py"
    src_file.write_text("print('X'*1000)\n", 'utf-8')
    img_src = IMAGEKEYS_DIR / "medium_res.jpg"
    img_dest = tmp_path / "key_medium.jpg"
    assert img_src.exists(), f"Image file not found: {img_src}"
    shutil.copy(img_src, img_dest)
    locked = tmp_path / "locked.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    subprocess.run([
        "python", "-m", "engine.encryptor_core", "--input", str(src_file), "--image", str(img_dest), "--output", str(locked)
    ], check=True, cwd=PROJECT_ROOT, env=env)
    data = base64.b64decode(re.search(r'ENCRYPTED_PAYLOAD = "([^"]+)"', locked.read_text()).group(1))
    ent = compute_entropy(data)
    assert ent >= 7.5  # For medium tier 