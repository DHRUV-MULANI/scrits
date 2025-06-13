import os
import shutil
import subprocess
import time
import base64
from pathlib import Path

CODE_SIZES = [1024, 100*1024, 1024*1024]  # 1 KB, 100 KB, 1 MB
TIERS = [
    ("low_res.jpg", "low"),
    ("medium_res.jpg", "medium"),
    ("high_res_sample.jpg", "high"),
]

RESULTS = []

os.makedirs("benchmarks/tmp", exist_ok=True)

for code_size in CODE_SIZES:
    # Generate dummy Python code of the given size
    code = ("print('A')\n" * (code_size // 10))[:code_size]
    src_file = Path("benchmarks/tmp/test.py")
    src_file.write_text(code, encoding='utf-8')
    for img_name, tier in TIERS:
        img_src = Path(f"imagekeys/{img_name}")
        img_dest = Path("benchmarks/tmp/key.jpg")
        shutil.copy(img_src, img_dest)
        locked_file = Path("benchmarks/tmp/locked.py")
        decrypted_file = Path("benchmarks/tmp/dec.py")

        # Encryption timing
        t0 = time.perf_counter()
        subprocess.run([
            "python", "engine/encryptor_core.py",
            str(src_file), str(img_dest), str(locked_file)
        ], check=True)
        t1 = time.perf_counter()
        enc_time = t1 - t0
        locked_size = locked_file.stat().st_size

        # Execution timing
        t2 = time.perf_counter()
        run = subprocess.run(["python", str(locked_file)], capture_output=True, text=True)
        t3 = time.perf_counter()
        exec_time = t3 - t2

        # Decryption timing
        t4 = time.perf_counter()
        subprocess.run([
            "python", "engine/decryptor_core.py",
            str(locked_file), str(img_dest),
            "--out", str(decrypted_file)
        ], check=True)
        t5 = time.perf_counter()
        dec_time = t5 - t4

        # Record result
        RESULTS.append({
            "code_size": code_size,
            "tier": tier,
            "locked_size": locked_size,
            "enc_time": enc_time,
            "exec_time": exec_time,
            "dec_time": dec_time,
            "success": run.returncode == 0
        })

# Output as markdown table
print("| Code Size | Tier   | Locked Size | Enc Time (s) | Exec Time (s) | Dec Time (s) | Success |")
print("|-----------|--------|-------------|--------------|---------------|--------------|---------|")
for r in RESULTS:
    print(f"| {r['code_size']} | {r['tier']} | {r['locked_size']} | {r['enc_time']:.3f} | {r['exec_time']:.3f} | {r['dec_time']:.3f} | {r['success']} |") 