# Source fragments for generate_solution.py; do not run this file directly.

# template: SHA256
def digest_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# template: SHA1
def digest_text(text):
    return hashlib.sha1(text.encode()).hexdigest()

# template: MD5
def digest_text(text):
    return hashlib.md5(text.encode()).hexdigest()

# template: CUSTOM32
def digest_text(text):
    value = 5381
    for byte in text.encode():
        value = ((value * 33) + byte) & 0xffffffff
    return f"{value:08x}"

# template: SHA512
def digest_text(text):
    return hashlib.sha512(text.encode()).hexdigest()
