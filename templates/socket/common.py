"""Small shared crypto and framed-socket helpers for the generated demo."""
import hashlib
import hmac
import json
import math
import secrets
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
MAX_FRAME = 4 * 1024 * 1024
MAX_MESSAGE_BYTES = 1_000_000
BALLOTS_PATH = DATA / "ballots.json"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def paillier_keypair(bits=2048):
    """Create an educational Paillier key pair for additive vote tallies."""
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    while q == p:
        q = getPrime(bits // 2)
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)  # g = n + 1 makes L(g^lambda mod n^2) = lambda.
    return ({"n": str(n), "g": str(n + 1)},
            {"n": str(n), "lambda": str(lam), "mu": str(mu)})


def paillier_encrypt(value, public_key):
    n, g = int(public_key["n"]), int(public_key["g"])
    if not 0 <= value < n:
        raise ValueError("Vote value is outside the Paillier message range.")
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return str((pow(g, value, n * n) * pow(r, n, n * n)) % (n * n))


def paillier_add(ciphertexts, public_key):
    n = int(public_key["n"])
    modulus = n * n
    product = 1
    for ciphertext in ciphertexts:
        value = int(ciphertext)
        if not 0 < value < modulus:
            raise ValueError("Invalid Paillier ciphertext.")
        product = product * value % modulus
    return str(product)


def paillier_decrypt(ciphertext, private_key):
    n, lam, mu = (int(private_key[key]) for key in ("n", "lambda", "mu"))
    value = int(ciphertext)
    if not 0 < value < n * n:
        raise ValueError("Invalid Paillier ciphertext.")
    powered = pow(value, lam, n * n)
    return (((powered - 1) // n) * mu) % n


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def hash_bytes(data):
    algorithms = {"SHA256": hashlib.sha256, "SHA512": hashlib.sha512,
                  "SHA1": hashlib.sha1, "MD5": hashlib.md5}
    if HASH_ALGORITHM == "CUSTOM32":
        value = 5381
        for byte in data:
            value = ((value * 33) + byte) & 0xffffffff
        return f"{value:08x}"
    return algorithms[HASH_ALGORITHM](data).hexdigest()


def constituency_index(value):
    """Build the deterministic HMAC token used by the searchable index."""
    normalized = value.strip().casefold().encode("utf-8")
    return hmac.new(bytes.fromhex(SEARCH_INDEX_KEY), normalized, hashlib.sha256).hexdigest()


def seal(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": cipher.nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}


def unseal(key, record):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(record["nonce"]))
    return cipher.decrypt_and_verify(bytes.fromhex(record["ciphertext"]), bytes.fromhex(record["tag"]))


def elgamal_sign(value, private_key):
    p, g, x = int(private_key["p"]), int(private_key["g"]), int(private_key["x"])
    k = secrets.randbelow(p - 2) + 1
    while math.gcd(k, p - 1) != 1:
        k = secrets.randbelow(p - 2) + 1
    r = pow(g, k, p)
    s = (int(value, 16) - x * r) * pow(k, -1, p - 1) % (p - 1)
    return [str(r), str(s)]


def elgamal_verify(value, signature, public_key):
    p, g, y = int(public_key["p"]), int(public_key["g"]), int(public_key["y"])
    r, s = map(int, signature)
    return (0 < r < p and 0 <= s < p - 1 and
            pow(g, int(value, 16), p) == pow(y, r, p) * pow(r, s, p) % p)


def signature_challenge(value, commitment):
    return int(hash_bytes(canonical([value, str(commitment)])), 16) % SIG_Q


def user_sign(value, private_key):
    if SIGNATURE_ALGORITHM == "RSA":
        key = RSA.import_key(private_key) if isinstance(private_key, (str, bytes)) else private_key
        return pss.new(key).sign(SHA256.new(value.encode())).hex()
    if SIGNATURE_ALGORITHM == "ElGamal":
        return elgamal_sign(value, private_key)
    nonce = secrets.randbelow(SIG_Q - 1) + 1
    commitment = pow(SIG_G, nonce, SIG_P)
    challenge = signature_challenge(value, commitment)
    return [str(commitment), str((nonce + challenge * int(private_key)) % SIG_Q)]


def user_verify(value, signature, public_key):
    try:
        if SIGNATURE_ALGORITHM == "RSA":
            pss.new(RSA.import_key(public_key)).verify(SHA256.new(value.encode()), bytes.fromhex(signature))
            return True
        if SIGNATURE_ALGORITHM == "ElGamal":
            return elgamal_verify(value, signature, public_key)
        commitment, response = map(int, signature)
        if not (0 < commitment < SIG_P and 0 <= response < SIG_Q):
            return False
        challenge = signature_challenge(value, commitment)
        return pow(SIG_G, response, SIG_P) == commitment * pow(int(public_key), challenge, SIG_P) % SIG_P
    except (ValueError, TypeError, KeyError):
        return False


def symmetric_key_bytes():
    return {"AES-128": 16, "AES-192": 24, "AES-256": 32,
            "DES": 8, "Triple-DES": 24}[SYMMETRIC_ALGORITHM]


def new_symmetric_key():
    while True:
        key = secrets.token_bytes(symmetric_key_bytes())
        if SYMMETRIC_ALGORITHM != "Triple-DES":
            return key
        try:
            return DES3.adjust_key_parity(key)
        except ValueError:
            continue


def _block_cipher(key, iv=None):
    module = AES if SYMMETRIC_ALGORITHM.startswith("AES") else (DES if SYMMETRIC_ALGORITHM == "DES" else DES3)
    return module.new(key, module.MODE_CBC, iv=iv) if iv is not None else module.new(key, module.MODE_CBC)


def cbc_encrypt(data, key):
    cipher = _block_cipher(key)
    return {"iv": cipher.iv.hex(), "ciphertext": cipher.encrypt(pad(data, cipher.block_size)).hex()}


def cbc_decrypt(record, key):
    cipher = _block_cipher(key, iv=bytes.fromhex(record["iv"]))
    return unpad(cipher.decrypt(bytes.fromhex(record["ciphertext"])), cipher.block_size)


def recv_exact(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ValueError("Connection closed before the full message arrived.")
        chunks.extend(chunk)
    return bytes(chunks)


def receive(connection):
    size = struct.unpack("!I", recv_exact(connection, 4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("Invalid message size.")
    return json.loads(recv_exact(connection, size))


def send(connection, value):
    data = canonical(value)
    if len(data) > MAX_FRAME:
        raise ValueError("Message is too large.")
    connection.sendall(struct.pack("!I", len(data)) + data)


def request(config, public, payload):
    key = secrets.token_bytes(32)
    server_key = RSA.import_key(public["server_rsa"])
    wrapped = PKCS1_OAEP.new(server_key, hashAlgo=SHA256).encrypt(key).hex()
    with socket.create_connection((config["host"], config["port"]), timeout=30) as connection:
        connection.settimeout(30)
        send(connection, {"wrapped_key": wrapped, "payload": seal(key, canonical(payload))})
        response = json.loads(unseal(key, receive(connection)))
    if not response["ok"]:
        raise ValueError(response["error"])
    return response["result"]
