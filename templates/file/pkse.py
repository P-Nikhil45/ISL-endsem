# PKSE source fragment; loaded as text by the generator.
# Lab 8 exercise 2: Paillier-encrypted keyword hashes and document IDs.
# This local teaching demo scans the index using the private key. It is not
# a server-side trapdoor/PEKS protocol. Randomized ciphertexts cannot be
# compared directly for equality.
def initialize_pkse():
    global PKSE_N, PKSE_N2, PKSE_LAMBDA, PKSE_MU
    key_file = BASE / "keys" / "pkse.json"
    if key_file.exists():
        state = json.loads(key_file.read_text(encoding="utf-8"))
        p, q = int(state["p"]), int(state["q"])
    else:
        while True:
            p, q = getPrime(1024), getPrime(1024)
            if p != q and math.gcd(math.lcm(p - 1, q - 1), p * q) == 1:
                break
        key_file.write_text(json.dumps({"p": str(p), "q": str(q)}), encoding="utf-8")
    PKSE_N = p * q
    PKSE_N2 = PKSE_N * PKSE_N
    PKSE_LAMBDA = math.lcm(p - 1, q - 1)
    # With g = n + 1, L(g^lambda mod n^2) = lambda mod n.
    PKSE_MU = pow(PKSE_LAMBDA, -1, PKSE_N)


def pkse_encrypt(message):
    if not 0 <= message < PKSE_N:
        raise ValueError("PKSE integer is outside the public-key range.")
    r = secrets.randbelow(PKSE_N - 1) + 1
    while math.gcd(r, PKSE_N) != 1:
        r = secrets.randbelow(PKSE_N - 1) + 1
    return ((1 + PKSE_N * message) * pow(r, PKSE_N, PKSE_N2)) % PKSE_N2


def pkse_decrypt(ciphertext):
    if not 0 < ciphertext < PKSE_N2 or math.gcd(ciphertext, PKSE_N) != 1:
        raise ValueError("Invalid PKSE ciphertext.")
    value = pow(ciphertext, PKSE_LAMBDA, PKSE_N2)
    return ((value - 1) // PKSE_N * PKSE_MU) % PKSE_N


def pkse_encrypt_id(filename):
    data = filename.encode("utf-8")
    chunk_size = (PKSE_N.bit_length() - 1) // 8
    return [str(pkse_encrypt(int.from_bytes(data[i:i + chunk_size], "big")))
            for i in range(0, len(data), chunk_size)]


def pkse_decrypt_id(chunks):
    parts = []
    for chunk in chunks:
        value = pkse_decrypt(int(chunk))
        parts.append(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    return b"".join(parts).decode("utf-8")


def create_index(documents, key=None, iv=None):
    postings = {}
    for filename, text in documents.items():
        for word in set(text.lower().split()):
            digest = int.from_bytes(hashlib.sha256(word.encode()).digest(), "big")
            postings.setdefault(digest, []).append(filename)
    index = {"scheme": "PKSE", "public_n": str(PKSE_N), "entries": []}
    for digest, filenames in postings.items():
        index["entries"].append({"keyword": str(pkse_encrypt(digest)),
                                 "documents": [pkse_encrypt_id(name) for name in filenames]})
    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return index


def search(index, query, key=None, documents=None):
    if index.get("scheme") != "PKSE" or index.get("public_n") != str(PKSE_N):
        raise ValueError("The search index does not match the PKSE keys. Rebuild the index.")
    query_hash = int.from_bytes(hashlib.sha256(query.strip().lower().encode()).digest(), "big")
    encrypted_query = pkse_encrypt(query_hash)
    inverse_query = pow(encrypted_query, -1, PKSE_N2)
    results = []
    for entry in index["entries"]:
        encrypted_keyword = int(entry["keyword"])
        if not 0 < encrypted_keyword < PKSE_N2:
            raise ValueError("Invalid PKSE keyword ciphertext.")
        # E(keyword) / E(query) encrypts their difference modulo n.
        difference = encrypted_keyword * inverse_query % PKSE_N2
        if pkse_decrypt(difference) == 0:
            for encrypted_id in entry["documents"]:
                filename = pkse_decrypt_id(encrypted_id)
                results.append((filename, read_document(filename)))
    return results
