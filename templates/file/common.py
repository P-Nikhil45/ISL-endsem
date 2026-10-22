# Shared source fragments; loaded as text, never imported.

# template: SSE - CREATE ENCRYPTED INDEX AND SEARCH
def token(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def create_index(documents, key, iv=None):
    index = {}
    for doc_id, doc in documents.items():
        for word in set(doc.lower().split()):
            record_iv = get_random_bytes(BLOCK_CIPHER.block_size)
            enc_id = symmetric_encrypt(doc_id, key, record_iv)
            index.setdefault(token(SEARCH_KEY, word), []).append((record_iv.hex(), enc_id))
    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return index


def search(index, query, key, documents=None):
    results = []
    for iv_hex, enc_id in index.get(token(SEARCH_KEY, query.strip()), []):
        doc_id = symmetric_decrypt(enc_id, key, bytes.fromhex(iv_hex))
        results.append((doc_id, read_document(doc_id)))
    return results

# template: FILE STORAGE
def initialize():
    global SERVER_RSA, SERVER_ECC, PRIVATE_X, PUBLIC_Y
    for name in ("encrypted", "hashes", "signature", "public_key", "add", "metadata", "keys"):
        (BASE / name).mkdir(parents=True, exist_ok=True)
    key_file = BASE / "keys" / "local.json"
    if key_file.exists():
        state = json.loads(key_file.read_text())
    else:
        state = {"symmetric": get_random_bytes(KEY_BYTES).hex(),
                 "search": get_random_bytes(32).hex()}
        if ASYMMETRIC == "RSA":
            state["private"] = RSA.generate(2048).export_key().decode()
        elif ASYMMETRIC == "ECDH":
            state["private"] = ECC.generate(curve="P-256").export_key(format="PEM")
        else:
            state["private"] = secrets.randbelow(P - 3) + 2
        key_file.write_text(json.dumps(state), encoding="utf-8")
    if ASYMMETRIC == "RSA":
        SERVER_RSA = RSA.import_key(state["private"])
    elif ASYMMETRIC == "ECDH":
        SERVER_ECC = ECC.import_key(state["private"])
    else:
        PRIVATE_X = state["private"]
        PUBLIC_Y = pow(G, PRIVATE_X, P)
    if SEARCH_SCHEME == "PKSE":
        initialize_pkse()
    return bytes.fromhex(state["symmetric"]), bytes.fromhex(state["search"])


def record_path(folder, filename):
    if (not filename or filename in (".", "..") or
            any(ch in filename for ch in '<>:"/\\|?*') or
            filename.endswith((".", " ")) or
            filename.split('.')[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
             *[f"LPT{i}" for i in range(1, 10)]}):
        raise ValueError("Enter a plain filename, for example report1.txt")
    return BASE / folder / filename


def write_file(folder, filename, value):
    record_path(folder, filename).write_text(value, encoding="utf-8")


def read_file(folder, filename):
    return record_path(folder, filename).read_text(encoding="utf-8")


def load_documents():
    documents = {}
    for file in (BASE / "encrypted").iterdir():
        if file.is_file():
            try:
                documents[file.name] = read_document(file.name)
            except (ValueError, OSError, KeyError, TypeError):
                print("Skipping invalid document:", file.name)
    return documents

# template: STUDENT
def student(filename, plaintext, num1, num2, key, iv):
    if record_path("encrypted", filename).exists():
        raise ValueError("Document already exists!")
    homomorphic, homomorphic_time = timed_operation(calculate_homomorphic, num1, num2)
    # A fresh IV is stored for each record.
    iv = get_random_bytes(BLOCK_CIPHER.block_size)
    ciphertext, encryption_time = timed_operation(symmetric_encrypt, plaintext, key, iv)
    hash_value, hashing_time = timed_operation(digest_text, ciphertext)
    private_key, public_key = generate_keys()
    signature = sign_message(ciphertext, private_key)
    metadata = {"iv": iv.hex(), "wrapped_key": wrap_key(key), "num1": num1, "num2": num2,
                "timings": {"encryption": encryption_time, "hashing": hashing_time,
                            "homomorphic": homomorphic_time},
                "events": []}
    write_file("encrypted", filename, ciphertext)
    metadata["created_at"] = timestamp()
    write_file("hashes", filename, hash_value)
    write_file("signature", filename, json.dumps(signature))
    write_file("public_key", filename, json.dumps(public_key))
    write_file("add", filename, json.dumps(homomorphic))
    write_file("metadata", filename, json.dumps(metadata))
    record_event(filename, "creation completed")
    print_heading("Document created", filename)
    print_detail("Created at", display_timestamp(metadata["created_at"]))
    print_detail("Encrypted text (hex)", ciphertext)
    print_detail("Ciphertext hash", hash_value)
    print_duration("Encryption time", encryption_time)
    print_duration("Hashing time", hashing_time)
    print_duration("Homomorphic computation time", homomorphic_time)

# template: READ DOCUMENT
def verify_document(filename, show_details=False):
    ciphertext = read_file("encrypted", filename)
    actual_hash, hashing_time = timed_operation(digest_text, ciphertext)
    try:
        stored_hash = read_file("hashes", filename)
        if show_details:
            print_detail("Encrypted text (hex)", ciphertext)
            print_detail("Stored ciphertext hash", stored_hash)
            print_detail("Computed ciphertext hash", actual_hash)
        if actual_hash != stored_hash:
            raise ValueError("Integrity verification failed.")
        signature = json.loads(read_file("signature", filename))
        public_key = json.loads(read_file("public_key", filename))
        if not verify_signature(ciphertext, signature, public_key):
            raise ValueError("Digital signature verification failed.")
    except (ValueError, OSError, KeyError, TypeError):
        event = record_event(filename, "verification", "failed", hashing_time)
        if show_details:
            print_verification(event)
        raise
    event = record_event(filename, "verification", timing=hashing_time)
    if show_details:
        print_verification(event)
    return ciphertext


def read_document(filename, show_details=False):
    ciphertext = verify_document(filename, show_details=show_details)
    metadata = json.loads(read_file("metadata", filename))
    key = unwrap_key(metadata["wrapped_key"])
    plaintext = symmetric_decrypt(ciphertext, key, bytes.fromhex(metadata["iv"]))
    event = record_event(filename, "decrypted")
    if show_details:
        print_detail("Decrypted at", display_timestamp(event["timestamp"]))
    return plaintext

# template: FACULTY
def faculty(filename, num1=None, num2=None, key=None, iv=None):
    print_heading("Verify and decrypt", filename)
    plaintext = read_document(filename, show_details=True)
    metadata = json.loads(read_file("metadata", filename))
    homomorphic = json.loads(read_file("add", filename))
    result = decrypt_homomorphic(homomorphic["ciphertext"])
    expected = expected_homomorphic(metadata["num1"], metadata["num2"])
    print_detail("Homomorphic result", result)
    if result != expected:
        record_event(filename, "homomorphic verification", "failed")
        raise ValueError("Homomorphic verification failed.")
    event = record_event(filename, "homomorphic verification")
    print_detail("Homomorphic check", "Passed")
    print_detail("Checked at", display_timestamp(event["timestamp"]))
    record_event(filename, "viewed")
    print("\nDocument text:")
    print(plaintext)
    return plaintext

# template: HOD
def hod(filename):
    print_heading("Verify document", filename)
    try:
        verify_document(filename, show_details=True)
        result = True
    except ValueError:
        result = False
    return result

# template: MAIN MENU
def main():
    global SEARCH_KEY
    key, SEARCH_KEY = initialize()
    documents = load_documents()
    num1=0
    num2=0
    iv = None
    create_index(documents, key)
    while True:

        print("\n" + "=" * 40)
        print("             " + TITLE)
        print("=" * 40)
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        print("=" * 40)

        choice = input("Enter choice: ")

        if choice == "1":

            while True:
                print("\n------ Student Menu ------")
                print("1. Add a new document")
                print("2. View documents")
                print("3. Back to main menu")
                print("4. Classical cipher demonstration")

                student_choice = input("Enter choice: ")

                if student_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename == "":
                        print("Filename cannot be empty.")
                        continue

                    if filename in documents:
                        print("Document already exists!")
                        continue

                    plaintext = input("Enter document record: ")


                    try:
                        num1 = int(input("Enter first integer: "))
                        num2 = int(input("Enter second integer: "))
                    except ValueError:
                        print("Enter valid integers.")
                        continue

                    try:
                        student(filename, plaintext, num1, num2, key, iv)
                        documents[filename] = plaintext
                        create_index(documents, key)
                    except (ValueError, OSError) as exc:
                        print(exc)

                elif student_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        print("\n------ All Documents ------")

                        for filename, plaintext in documents.items():
                            try:
                                view_document(filename)
                            except (ValueError, OSError, KeyError, TypeError) as exc:
                                print(exc)
                elif student_choice == "4":
                    try:
                        result = classical_demo(input("Enter classical cipher text: "))
                        print("Ciphertext:", result["ciphertext"])
                        print("Decrypted text:", result["decrypted_text"])
                    except ValueError as exc:
                        print(exc)

                elif student_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "2":

            while True:
                print("\n------ Faculty Menu ------")
                print("1. Verify and decrypt a document")
                print("2. Search documents")
                print("3. Back to main menu")

                faculty_choice = input("Enter choice: ")

                if faculty_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename not in documents:
                        print("Document not found!")
                        continue


                    try:
                        faculty(filename)
                    except (ValueError, OSError, KeyError, TypeError) as exc:
                        print(exc)

                elif faculty_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        search_text = input("Search word: ").lower()
                        encrypted_index = json.loads((BASE / "index.json").read_text())
                        try:
                            results = search(encrypted_index, search_text, key, documents)
                        except (ValueError, OSError, KeyError, TypeError) as exc:
                            print(exc)
                            continue


                        if results:
                            for doc_id, doc in results:
                                show_search_result(doc_id, doc)
                        else:
                            print("No matching documents found")


                elif faculty_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "3":

            filename = input("Enter filename: ")

            try:
                hod(filename)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                print(exc)

        elif choice == "4":

            print("\nExiting " + TITLE + "...")
            break

        else:

            print("\nInvalid choice. Please try again.")

# template: PROGRAM START
if __name__ == "__main__":
    main()

# template: symmetric
def symmetric_encrypt(plaintext, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext.encode(), BLOCK_CIPHER.block_size)).hex()


def symmetric_decrypt(ciphertext_hex, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), BLOCK_CIPHER.block_size).decode()

# template: imports
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pathlib import Path
from math import gcd
import random
import secrets
import hashlib
import hmac
import math
import base64
import json
import re
from datetime import datetime
from time import perf_counter

# template: TIMESTAMPS AND TIMINGS
def timestamp():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def timed_operation(operation, *args):
    started_at = timestamp()
    start = perf_counter()
    result = operation(*args)
    elapsed_ms = (perf_counter() - start) * 1000
    return result, {"started_at": started_at, "completed_at": timestamp(),
                    "elapsed_ms": elapsed_ms}


def record_event(filename, action, status="success", timing=None):
    metadata = json.loads(read_file("metadata", filename))
    event = {"action": action, "status": status, "timestamp": timestamp()}
    if timing is not None:
        event["hashing"] = timing
    metadata.setdefault("events", []).append(event)
    write_file("metadata", filename, json.dumps(metadata))
    return event


def display_timestamp(value):
    if not value:
        return "Not recorded (older record)"
    dt = datetime.fromisoformat(value)
    offset = dt.strftime("%z")
    zone = " UTC" + offset[:3] + ":" + offset[3:] if offset else ""
    return dt.strftime("%d %b %Y, %I:%M:%S %p") + zone


def print_heading(title, filename):
    print("\n" + title)
    print("-" * 48)
    print_detail("File", filename)


def print_detail(label, value):
    print(f"  {label:<32}: {value}")


def print_duration(label, timing):
    value = f"{timing['elapsed_ms']:.6f} ms" if timing else "Not recorded (older record)"
    print_detail(label, value)


def print_verification(event):
    print_detail("Hash and signature check", "Passed" if event["status"] == "success" else "Failed")
    print_detail("Verification time", display_timestamp(event["timestamp"]))
    print_duration("Hashing time", event.get("hashing"))


def show_search_result(filename, plaintext):
    record_event(filename, "viewed in search")
    metadata = json.loads(read_file("metadata", filename))
    print_heading("Search result", filename)
    # Show the record's stored computation duration, not search duration.
    print_duration("Homomorphic time (at creation)", metadata.get("timings", {}).get("homomorphic"))
    print("\nDocument text:")
    print(plaintext)


def view_document(filename):
    plaintext = read_document(filename)
    event = record_event(filename, "viewed")
    metadata = json.loads(read_file("metadata", filename))
    print_heading("View document", filename)
    print_detail("Created at", display_timestamp(metadata.get("created_at")))
    print_detail("Viewed at", display_timestamp(event["timestamp"]))
    print("\nDocument text:")
    print(plaintext)
    return plaintext
