# CodeMorpherAI-X

## Overview
CodeMorpherAI-X encrypts source code from any language using a user-supplied image as a key, producing an unreadable but still executable file. Only someone with the exact same image can decrypt and view the original source code using the Viewer tool.

## Directory Structure
- `engine/` - Core engine modules
- `templates/` - Loader templates for supported languages
- `input/` - Place your source code here
- `imagekeys/` - Place your passkey images here
- `output/` - Encrypted and decrypted files
- `docs/` - Documentation

## Usage

### Encryptor
```bash
python engine/encryptor_core.py --input input/your_code.xxx --image imagekeys/passkey_image.jpg --output output/locked_code.xxx
```

### Viewer/Decryptor
```bash
python engine/decryptor_core.py --input output/locked_code.xxx --image imagekeys/passkey_image.jpg --output output/decrypted_source.xxx
```

## Requirements
See `requirements.txt` for dependencies. 