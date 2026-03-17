# ENCDEC - Secure File Encryptor/Decryptor (Tkinter GUI)

A simple Python desktop app that encrypts and decrypts files using a GUI (Tkinter).  
Supports multiple algorithms via **PyCryptodome**: `AES`, `DES`, `3DES`, `Blowfish`, and `RSA`.

## Features

- GUI-based file selection (no CLI needed)
- Encrypt files to `*.enc`
- Save key material to `*.key` files
- Decrypt `*.enc` back to `*_decrypted.txt`
- Algorithm picker: AES / DES / 3DES / Blowfish / RSA

## Requirements

- Python 3.x
- `pycryptodome` (provides the `Crypto` module)

Install dependency:

```bash
pip install pycryptodome
```

## Run

```bash
python app2.py
```

## How To Use

1. Open the app.
2. Choose an algorithm from the dropdown.
3. Click **Browse** and select a file.
4. Click **Encrypt**:
   - Creates an encrypted file next to the original with `.enc` appended.
   - Creates one or more key files in the current working directory (see below).
5. To decrypt:
   - Select the encrypted `*.enc` file in the app.
   - Click **Decrypt** and pick the matching key file when prompted.

## Output Files (What Gets Created)

For symmetric algorithms (`AES`, `DES`, `3DES`, `Blowfish`):

- Encrypted file: `yourfile.ext.enc`
- Key file: `key_yourfile.ext.key` (saved in the directory you run the app from)

For `RSA`:

- Encrypted file: `yourfile.ext.enc`
- Private key file: `private_key_yourfile.ext.key` (pick this when decrypting)
- Public key file: `public_key_yourfile.ext.key`

Decryption output:

- `yourfile.ext_decrypted.txt`

Symmetric encryption file layout:

- `nonce` (16 bytes) + `tag` (16 bytes) + `ciphertext`

## Notes / Limitations

- `RSA` encryption in this project uses OAEP on the whole file content. That only works for *very small* files (RSA cannot encrypt large blobs directly).  
  If you want RSA for real files, the usual approach is *hybrid encryption* (RSA encrypts an AES key, AES encrypts the file).
- Keep `.key` files safe. Anyone with the key can decrypt the data.
- Do not commit real keys to GitHub. Add `*.key` and `*.enc` to `.gitignore` for safety.

## Keywords (GitHub Topics)

`python`, `tkinter`, `file-encryption`, `file-decryption`, `cryptography`, `pycryptodome`, `aes`, `des`, `3des`, `blowfish`, `rsa`, `oaep`, `desktop-app`, `security`, `encryption-tool`
