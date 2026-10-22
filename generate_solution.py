"""Generate a standalone file-based crypto lab by choosing algorithm names.
Run: python generate_solution.py
Only the generated solution requires pycryptodome. This generator uses the
standard library and reads Python source fragments from templates/file/.
"""
from pathlib import Path
import ast
import json
import re

# Templates are ordinary Python files so their code is easy to read and edit.
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "file"


def load_templates(filename):
    """Read named Python fragments without importing or executing them."""
    source = (TEMPLATE_DIR / filename).read_text(encoding="utf-8")
    result = {}
    for block in source.split("# template: ")[1:]:
        label, code = block.split("\n", 1)
        path = label.strip().split("/")
        target = result
        for name in path[:-1]:
            target = target.setdefault(name, {})
        target[path[-1]] = code.strip()
    return result


TEMPLATES = {
    category: load_templates(category + ".py")
    for category in ("classical", "symmetric", "asymmetric", "hash", "signature", "homomorphic")
}
COMMON = load_templates("common.py")
PKSE_TEMPLATE = (TEMPLATE_DIR / "pkse.py").read_text(encoding="utf-8")


OPTIONS = {
    "classical": ("Vigenere", "Additive", "Multiplicative", "Affine", "Autokey", "Playfair", "Hill", "Transposition"),
    "symmetric": ("AES-128", "AES-192", "AES-256", "DES", "Triple-DES"),
    "hash": ("SHA256", "SHA512", "SHA1", "MD5", "CUSTOM32"),
    "asymmetric": ("RSA", "ElGamal", "ECDH", "DH"),
    "signature": ("RSA", "ElGamal", "Schnorr"),
    "homomorphic": ("Paillier", "RSA", "ElGamal"),
    "search": ("SSE", "PKSE"),
}
LABELS = {
    "classical": "Classical cipher demonstration",
    "symmetric": "Document encryption",
    "hash": "Ciphertext hashing",
    "asymmetric": "Key encryption / key agreement",
    "signature": "Digital signature",
    "homomorphic": "Homomorphic encryption",
    "search": "Searchable encryption",
}


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def canonical_algorithm(category, value):
    if category not in OPTIONS:
        raise ValueError("Unknown category: " + category)
    cleaned = normalize(value)
    aliases = {
        "symmetric": {"aes": "AES-128", "3des": "Triple-DES", "des3": "Triple-DES", "tdes": "Triple-DES"},
        "classical": {"caesar": "Additive", "vigenerecipher": "Vigenere", "columnar": "Transposition"},
        "asymmetric": {"rsaoaep": "RSA", "ecc": "ECDH", "diffiehellman": "DH"},
        "signature": {"rsapkcs1v15": "RSA"},
    }
    if cleaned in aliases.get(category, {}):
        return aliases[category][cleaned]
    for algorithm in OPTIONS[category]:
        if normalize(algorithm) == cleaned:
            return algorithm
    raise ValueError("Choose one of: " + ", ".join(OPTIONS[category]))


def choose_algorithm(category):
    print("\n" + LABELS[category])
    print("Options: " + " / ".join(OPTIONS[category]))
    if category == "asymmetric":
        print("DH/ECDH derive a shared key to protect the document key.")
    if category == "homomorphic":
        print("Paillier = addition; RSA / ElGamal = multiplication.")
    if category == "search":
        print("SSE = shared-key search; PKSE = Paillier public-key search (Lab 8).")
        print("Press Enter to use SSE.")
    while True:
        answer = input("Algorithm name: ").strip()
        if category == "search" and not answer:
            return "SSE"
        try:
            return canonical_algorithm(category, answer)
        except ValueError as exc:
            print(exc)


def section(title, code):
    return ("\n\n# =========================================================\n# " + title +
            "\n# =========================================================\n\n" + code.strip() + "\n")


def build_source(title, algorithms):
    selected = {name: canonical_algorithm(name, algorithms[name]) for name in OPTIONS}
    asymmetric = TEMPLATES["asymmetric"][selected["asymmetric"]]
    signature = dict(TEMPLATES["signature"][selected["signature"]])
    # Hash the ciphertext separately so timing excludes key generation/signing.
    signature["code"] = signature["code"].replace(", digest_text(message)", "").replace(", digest_text(content)", "")
    code = COMMON["imports"] + "\n\n# Standalone educational lab; local teaching keys are stored in keys/.\n"
    if selected["search"] == "PKSE":
        code += "from Crypto.Util.number import getPrime\n"
    code += "TITLE = " + repr(title) + "\n"
    code += "ASYMMETRIC = " + repr(selected["asymmetric"]) + "\n"
    code += "SEARCH_SCHEME = " + repr(selected["search"]) + "\n"
    code += "BASE = Path(__file__).resolve().parent\n"
    code += TEMPLATES["symmetric"][selected["symmetric"]] + "\n"
    code += asymmetric["constants"] + "\n" + signature["constants"] + "\n"
    search_code = PKSE_TEMPLATE if selected["search"] == "PKSE" else COMMON["SSE - CREATE ENCRYPTED INDEX AND SEARCH"]
    code += section(selected["search"] + " - CREATE ENCRYPTED INDEX AND SEARCH", search_code)
    code += section("HOMOMORPHIC ENCRYPTION AND DECRYPTION", TEMPLATES["homomorphic"][selected["homomorphic"]])
    code += section("GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE",
                    TEMPLATES["hash"][selected["hash"]] + "\n\n" + signature["code"])
    code += section(selected["symmetric"] + " ENCRYPTION AND DECRYPTION", COMMON["symmetric"])
    code += section(selected["asymmetric"] + " KEY PROTECTION", asymmetric["code"])
    code += section(selected["classical"] + " CLASSICAL CIPHER", TEMPLATES["classical"][selected["classical"]])
    for name in ("FILE STORAGE", "TIMESTAMPS AND TIMINGS", "STUDENT", "READ DOCUMENT", "FACULTY", "HOD", "MAIN MENU", "PROGRAM START"):
        code += section(name, COMMON[name])
    ast.parse(code)
    return code, selected


def create_solution(title, algorithms, output_dir):
    """Create a new folder only; never overwrite existing solutions or keys."""
    if not title.strip():
        raise ValueError("Enter a project name.")
    code, selected = build_source(title.strip(), algorithms)
    output_dir = Path(output_dir).resolve()
    # Do not reuse a directory: keys for different algorithms must stay separate.
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "solution.py").write_text(code, encoding="utf-8")
    (output_dir / "algos_used.json").write_text(json.dumps(selected, indent=2) + "\n", encoding="utf-8")
    (output_dir / "requirements.txt").write_text("pycryptodome>=3.20\n", encoding="utf-8")
    (output_dir / ".gitignore").write_text(
        "__pycache__/\n*.py[cod]\nkeys/\nencrypted/\nhashes/\nsignature/\npublic_key/\nadd/\nmetadata/\nindex.json\n",
        encoding="utf-8")
    guide = f"""{title.strip()} - FILE-BASED CRYPTO LAB

Run inside this folder:
  python -m pip install -r requirements.txt
  python solution.py

Algorithms:
""" + "\n".join(f"  {LABELS[k]}: {v}" for k, v in selected.items()) + """

Student: add/view records, or option 4 for the classical cipher demo.
Faculty: verify hash/signature, decrypt, check homomorphic result, search.
HoD: verify ciphertext hash and signature without decrypting the record.
Try report1.txt, text "fever treatment followup", and numbers 7 and 3.
Paillier produces 10; RSA and ElGamal produce 21. Search for fever.
The generated program is standalone: no generator or template files needed.

Files created when running the solution:
  encrypted/<filename>  : symmetric ciphertext in hexadecimal
  hashes/<filename>     : selected hash of ciphertext
  signature/<filename>  : digital signature of ciphertext
  public_key/<filename> : signature verification public key
  add/<filename>        : encrypted homomorphic result and operation
  metadata/<filename>   : IV, protected key, numbers, timestamps, timings, event history
  keys/local.json       : local symmetric, search and private key material
  keys/pkse.json        : separate Paillier search keys (PKSE only)
  index.json            : encrypted search index for the selected scheme

Search is case-insensitive and single-word, using whitespace tokenization.
SSE uses HMAC tokens and symmetric encryption of filenames.
PKSE follows Lab 8 exercise 2: Paillier encrypts keyword hashes and filenames.
The query hash is encrypted with the public key. An authorized local scan
decrypts homomorphic differences to find equal hashes, then decrypts matching
filenames with the private key. Randomized ciphertexts are not compared directly.
This is a local educational scan, not a server-side trapdoor/PEKS protocol.
PKSE search keys are separate from the selected record homomorphic algorithm.
Search tokens and signatures use SHA256 internally; your hash choice controls
only the separate ciphertext integrity hash. No network is used.
The classical cipher is a separate demo; it does not alter stored records.
Playfair merges I/J and retains fillers; Hill/transposition retain padding.

Paillier: inputs 0..322, addition modulo 323.
RSA homomorphic: inputs 0..142, multiplication modulo 143.
ElGamal homomorphic: inputs 1..466, multiplication modulo 467.
Key protection: RSA uses OAEP; ElGamal encrypts key bytes; DH/ECDH derive
an AES-EAX wrapping key. RSA signatures use a separate 2048-bit key pair.
Keys persist locally so records can be reopened after restart.
Timestamps include the local UTC offset and are saved with each record.
Creation, verification (including failures), decryption and viewing are logged.
Encryption and ciphertext hashing durations use a monotonic timer in milliseconds;
key generation and signing are excluded. Each operation shows only relevant details:
  Create: creation timestamp; encryption, hashing and homomorphic durations.
  View: creation and current viewing timestamps.
  Verify: current verification timestamp and hashing duration.
  Verify/decrypt: also shows decryption and homomorphic check timestamps.
  Search: only the saved homomorphic computation duration for each match.
The displayed record homomorphic duration was measured at creation, not search.
Full event history remains saved in metadata and is not printed automatically.
Older records without timing metadata display "Not recorded (older record)".
These are teaching examples with small groups and legacy algorithms.
Menus illustrate roles without login/access enforcement.
"""
    (output_dir / "RUN.txt").write_text(guide, encoding="utf-8")
    return output_dir / "solution.py"


def main():
    print("\nCRYPTO LAB SOLUTION GENERATOR")
    print("Enter algorithm names to create your own file-based solution.")
    print("Student / Faculty / HoD format, SSE or PKSE search, no network.")
    title = input("\nProject name (example: Hospital Reports): ").strip()
    while not title:
        title = input("Please enter a project name: ").strip()
    selected = {category: choose_algorithm(category) for category in OPTIONS}
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", title).strip("_")[:80] or "solution"
    default = Path(__file__).resolve().parent / "GENERATED_SOLUTIONS" / ("CUSTOM_" + slug)
    print("\nSelected algorithms:")
    for name, algorithm in selected.items():
        print("  " + LABELS[name] + ": " + algorithm)
    while True:
        print("\nOutput folder (Enter for " + str(default) + ")")
        answer = input("Folder: ").strip()
        output = Path(answer).expanduser() if answer else default
        try:
            file = create_solution(title, selected, output)
            break
        except FileExistsError:
            print("That folder already exists. Enter a NEW folder to preserve its files and keys.")
        except (OSError, ValueError) as exc:
            print("Could not create solution:", exc)
    print("\nCreated: " + str(file))
    print("Open its folder and run: python solution.py")
    print("If needed first run: python -m pip install -r requirements.txt")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGenerator closed.")
