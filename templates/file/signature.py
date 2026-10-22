# Source fragments for generate_solution.py; do not run this file directly.

# template: RSA/constants


# template: RSA/code
def generate_keys():
    private_key = RSA.generate(2048)
    return private_key, private_key.publickey().export_key().decode()


def sign_message(message, private_key):
    signature = pkcs1_15.new(private_key).sign(SHA256.new(message.encode()))
    return signature.hex(), digest_text(message)


def verify_signature(message, signature, public_key):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(SHA256.new(message.encode()), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False

# template: ElGamal/constants
SIG_P, SIG_G = 467, 2

# template: ElGamal/code
def generate_keys():
    private_key = secrets.randbelow(SIG_P - 2) + 1
    return private_key, pow(SIG_G, private_key, SIG_P)


def sign_message(content, private_key):
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    k = secrets.randbelow(SIG_P - 2) + 1
    while math.gcd(k, SIG_P - 1) != 1:
        k = secrets.randbelow(SIG_P - 2) + 1
    r = pow(SIG_G, k, SIG_P)
    s = ((value - private_key * r) * pow(k, -1, SIG_P - 1)) % (SIG_P - 1)
    return [r, s], digest_text(content)

def verify_signature(content, signature, public_key):
    r, s = signature
    if not (0 < r < SIG_P and 0 <= s < SIG_P - 1):
        return False
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    y = public_key
    return pow(SIG_G, value, SIG_P) == pow(y, r, SIG_P) * pow(r, s, SIG_P) % SIG_P

# template: Schnorr/constants
SIG_P, SIG_Q, SIG_G = (174603574791232246354051371231605080226102972426590404703484661759244705455687110144281032625687997348483286138744890049654307711880324095118542939269921608487240410973422511846587762698868714850355890367869802591444302651887017839068243795781065968467603192888664962425797716555608719325248493301139873058093, 1415788254246462573557326432318736449382436643643, 66532922375832765569458357633272330911524606757062802983006867719777963116922806290453422052521474726084041409076712888494723042566045983280507959282043750412503955630760900213914798970454838153641377939685649844204321345401500704230511993352319887249032829379614149535962443650838420750542008343644888130928)

# template: Schnorr/code
def generate_keys():
    private_key = secrets.randbelow(SIG_Q - 1) + 1
    return private_key, pow(SIG_G, private_key, SIG_P)


def challenge(content, commitment):
    message = json.dumps([content, commitment], ensure_ascii=False).encode()
    return int.from_bytes(hashlib.sha256(message).digest(), "big") % SIG_Q

def sign_message(content, private_key):
    k = secrets.randbelow(SIG_Q - 1) + 1
    r = pow(SIG_G, k, SIG_P)
    e = challenge(content, r)
    return [e, (k + private_key * e) % SIG_Q], digest_text(content)

def verify_signature(content, signature, public_key):
    e, s = signature
    if not (0 <= e < SIG_Q and 0 <= s < SIG_Q):
        return False
    y = public_key
    r = pow(SIG_G, s, SIG_P) * pow(pow(y, e, SIG_P), -1, SIG_P) % SIG_P
    return e == challenge(content, r)
