# Information Security Lab Generators

Generate runnable Python lab programs instead of navigating hundreds of prebuilt combinations.

**Start with [`generate_solution.py`](generate_solution.py)** for a single-computer, file-based lab. Use [`generate_socket_solution.py`](generate_socket_solution.py) for a menu-driven encrypted client/server voting demo.

## Quick start

Python **3.10+** is required. The generators use the standard library; generated cryptography programs need PyCryptodome.

```sh
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt
```

### File-based generator — the main entry point

```sh
python generate_solution.py
```

Enter a project name and choose algorithms. The generator creates a new folder containing `solution.py`, `requirements.txt`, `algos_used.json`, and `RUN.txt`. It never overwrites an existing output directory.

| Category | Choices |
| --- | --- |
| Classical demonstration | Vigenere, Additive, Multiplicative, Affine, Autokey, Playfair, Hill, Transposition |
| Document encryption | AES-128/192/256, DES, Triple-DES |
| Ciphertext hash | SHA256, SHA512, SHA1, MD5, CUSTOM32 |
| Key protection/agreement | RSA, ElGamal, ECDH, DH |
| Signature | RSA, ElGamal, Schnorr |
| Homomorphic arithmetic | Paillier addition, RSA or ElGamal multiplication |
| Search | SSE or Paillier-based PKSE |

Run the generated `solution.py` from its folder. Its Student / Faculty / HoD menus support creation, verification, decryption and search. Creation times and operation durations persist with records; each action prints only relevant details. Search shows the saved homomorphic computation duration, explicitly labeled as measured at creation. See the [file-generator guide](docs/file-generator.txt).

The file generator reads ordinary Python source fragments from `templates/file/`. Keep that folder beside the generator. Its role menus illustrate workflows; they do not enforce login or access control.

### Socket generator — encrypted voting workflow

Interactive:

```sh
python generate_socket_solution.py
```

Or generate directly:

```sh
python generate_socket_solution.py --output generated/voting_demo --title "Secure Voting Demo" --candidates 101,102,103 --encryption AES-128 --hashing SHA512 --verification ElGamal
cd generated/voting_demo
```

The generated folder contains only `server.py` and `client.py`. The generator lets you choose candidate IDs and ballot encryption (AES-128/192/256, DES, Triple-DES), hash (SHA256, SHA512, SHA1, MD5, CUSTOM32), and signature (RSA, ElGamal, Schnorr). It embeds fixed demonstration keys from `templates/socket/hardcoded_keys.json`, keeping server private keys in `server.py` and the client signing key in `client.py`.

Install PyCryptodome into the active virtual environment before running the generated programs:

```sh
python -m pip install "pycryptodome>=3.20,<5"
```

After setup completes, open two terminals in the generated folder. Start the server in one:

```sh
python server.py
```

In the other terminal, run the client:

```sh
python client.py
```

The client menu lets you cast a vote, search ballot receipts by constituency ID, tally votes for a constituency, or check server status. The server creates its ballot storage file when first run, verifies ballot hashes and signatures, and homomorphically adds encrypted candidate votes. Candidate selections remain encrypted in storage; the server can still decrypt individual votes because it holds the Paillier private key. Ballot timestamps are retained, but search filters only by constituency ID. See the [socket walkthrough](templates/socket/README.md) for limitations and run steps.

## Repository layout

```text
IS-ENDSEM/
├── generate_solution.py          # File-based generator entry point
├── generate_socket_solution.py   # Encrypted socket voting generator
├── templates/file/               # Readable file-based source fragments
├── templates/socket/             # Source copied into standalone socket labs
├── docs/                         # Usage and exam mapping
├── tests/test_generators.py      # Functional, crypto and socket checks
├── .github/workflows/tests.yml   # Automated checks on push / pull request
├── requirements.txt
└── README.md
```

Keep the corresponding `templates/file/` or `templates/socket/` folder beside each generator. Generated labs are standalone. The old lab collections, duplicate PDFs, temporary files and pre-generated combinations have been removed so the generators remain the focus.

## Verify changes

```sh
python -m unittest discover -s tests -v
```

Tests cover generated-source syntax and cryptographic helpers. The socket demo is intended for local educational use.

## Before pushing

Generated outputs, virtual environments, runtime data, private keys and editor caches are ignored. Inspect your changes with:

```sh
git status --short
git diff --check
```

The socket template includes fixed demonstration private keys, which are copied into generated role files. Do not use them outside this educational demo. The exam photograph and manuals are not redistributed. Review the configured Git remote before committing and pushing; the repository cleanup does not rewrite existing Git history.

## Scope

These are educational cryptography demonstrations, **not production security**. The socket demo has no voter login or account management. The generated client source contains the client signing key, and the generated server source contains the server transport and Paillier private keys. Keep those role files private and distribute them only to their intended roles. The server sees constituency and receipt time, and its Paillier key can decrypt individual candidate selections.
