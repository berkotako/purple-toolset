## encsim — Lab Encryption Simulator

A small, self-contained tool to simulate a ransomware-style file encryption event for SOC testing and training. It encrypts files in a target directory, writes a manifest for decryption, and drops a lab-only ransom note. No exfiltration; designed for safe, local testing.

### Requirements
- Rust (stable) with `cargo` installed
- Windows or any OS supported by the Rust toolchain

### Build
```bash
cargo build
```

### Quickstart (one-shot demo)
Runs: generate files → encrypt → decrypt → clean up.
```bash
cargo run -- demo
```

## Usage
Show CLI help:
```bash
cargo run -- --help
```

### Global flags
- `--dir <PATH>`: Directory to operate in (default: `./encsim_<timestamp>`)
- `--pass <PASSPHRASE>`: Derive key via Argon2id from a passphrase. If omitted, a random key is generated and stored in the manifest (lab-only convenience).
- `--count <N>`: Number of files for generation (default: 5)

### Commands
- `gen`: Create N random files in `--dir`.
- `encrypt`: Encrypt plaintext files in `--dir` and write `manifest.json`; drops a ransom note.
- `decrypt`: Decrypt files listed in a manifest and remove the ransom note.
- `demo`: Generate → encrypt → decrypt in one run.

## Common Workflows

### Generate sample files
```bash
cargo run -- gen --dir D:\test\encsim --count 10
```

### Encrypt with random lab key (stored in manifest)
```bash
cargo run -- encrypt --dir D:\test\encsim
```
Creates:
- `manifest.json` containing `algo`, `key_b64` (random 32-byte key, lab-only), and file entries
- Encrypted files (`.enc` or `<ext>.enc` suffix)
- `README_RECOVER_FILES.txt` ransom note

### Encrypt with passphrase (recommended for drills)
```bash
cargo run -- encrypt --dir D:\test\encsim --pass "S3curePassphrase!"
```
Creates:
- `manifest.json` containing `argon2_salt_b64` (no raw key)
- Same encrypted files and ransom note

### Decrypt
If you encrypted with a passphrase, you must supply the same one.
```bash
cargo run -- decrypt --dir D:\test\encsim --pass "S3curePassphrase!"
```
On success:
- Original plaintext files are restored
- Ciphertext files are removed
- Ransom note is removed

### Using a specific manifest path
```bash
cargo run -- decrypt --dir D:\test\encsim -- --manifest D:\test\encsim\manifest.json
```

## What the tool does
- Uses ChaCha20-Poly1305 (96-bit nonce, 256-bit key) for authenticated encryption.
- Key handling:
  - With `--pass`, derives a 32-byte key via Argon2id and stores the salt in the manifest.
  - Without `--pass`, generates a random 32-byte key and stores it as Base64 in the manifest (lab-only).
- Filenames:
  - Files with no extension get `.enc`.
  - Files with an extension `foo` become `.foo.enc`.
- Ransom note:
  - Writes `README_RECOVER_FILES.txt` after encryption; removed during successful decryption.

## SOC Exercise Notes
- Measure detection timing from when encrypted files and the ransom note appear.
- No network activity or exfiltration is performed by this tool.
- You can tune file counts and sizes by prepopulating the directory or using `gen` multiple times.

## Troubleshooting
- "no plaintext files to encrypt": The directory has only `.enc` files or `manifest.json`. Add files or run `gen`.
- "manifest expects a passphrase": Decryption requires the same `--pass` used for encryption.
- "argon2 derive failed" or "bad salt": Manifest mismatch/corruption; ensure you’re using the correct manifest and passphrase.

## Safety and Scope (Important)
- This is a lab simulator. It does not spread, persist, or exfiltrate data.
- Use only in controlled environments you own or are authorized to test.


