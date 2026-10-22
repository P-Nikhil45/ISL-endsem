# Source fragments for generate_solution.py; do not run this file directly.

# template: RSA/constants


# template: RSA/code
def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    return b64(PKCS1_OAEP.new(SERVER_RSA.publickey()).encrypt(key))

def unwrap_key(wrapped):
    return PKCS1_OAEP.new(SERVER_RSA).decrypt(unb64(wrapped))

# template: ElGamal/constants
P, G = 467, 2

# template: ElGamal/code
def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    pairs = []
    for byte in key:
        k = secrets.randbelow(P - 3) + 2
        pairs.append([pow(G, k, P), (byte + 1) * pow(PUBLIC_Y, k, P) % P])
    return pairs

def unwrap_key(wrapped):
    return bytes((b * pow(pow(a, PRIVATE_X, P), -1, P) % P) - 1
                 for a, b in wrapped)

# template: ECDH/constants


# template: ECDH/code
def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    # ECC hybrid encryption: ephemeral ECDH -> SHA256 -> AES key wrapping.
    ephemeral = ECC.generate(curve="P-256")
    point = SERVER_ECC.pointQ * ephemeral.d
    shared_key = hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [ephemeral.public_key().export_key(format="PEM"),
            b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public_pem, nonce, ciphertext, tag = wrapped
    point = ECC.import_key(public_pem).pointQ * SERVER_ECC.d
    shared_key = hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))

# template: DH/constants
P, G = 467, 2

# template: DH/code
def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    ephemeral = secrets.randbelow(P - 3) + 2
    public = pow(G, ephemeral, P)
    shared = pow(PUBLIC_Y, ephemeral, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [public, b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public, nonce, ciphertext, tag = wrapped
    shared = pow(public, PRIVATE_X, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))
