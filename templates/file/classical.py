# Source fragments for generate_solution.py; do not run this file directly.

# template: Vigenere
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    result, k = [], 0
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[k % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result, k = [], 0
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[k % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = vigenere_encrypt(text, "HEALTH")
    decrypted = vigenere_decrypt(encrypted, "HEALTH")
    return {"algorithm": "Vigenere", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Additive
def additive_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def additive_decrypt(ciphertext, key):
    return additive_encrypt(ciphertext, -key)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = additive_encrypt(text, 20)
    decrypted = additive_decrypt(encrypted, 20)
    return {"algorithm": "Additive", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Multiplicative
def multiplicative_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def multiplicative_decrypt(ciphertext, key):
    key_inv = pow(key, -1, 26)
    result = []
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base) * key_inv % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = multiplicative_encrypt(text, 15)
    decrypted = multiplicative_decrypt(encrypted, 15)
    return {"algorithm": "Multiplicative", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Affine
def affine_encrypt(plaintext, a, b):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def affine_decrypt(ciphertext, a, b):
    a_inv = pow(a, -1, 26)
    result = []
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(a_inv * (ord(ch) - base - b) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = affine_encrypt(text, 15, 20)
    decrypted = affine_decrypt(encrypted, 15, 20)
    return {"algorithm": "Affine", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Autokey
def letters_only_upper(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

def autokey_encrypt(plaintext, seed_key):
    seed_key = seed_key.upper()
    running_key = seed_key + letters_only_upper(plaintext)
    result, k = [], 0
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(running_key[k]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def autokey_decrypt(ciphertext, seed_key):
    seed_key = seed_key.upper()
    running_key = list(seed_key)
    result, k = [], 0
    for ch in ciphertext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(running_key[k]) - ord('A')
            plain_letter_upper = chr((ord(ch) - base - shift) % 26 + ord('A'))
            running_key.append(plain_letter_upper)
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            k += 1
        else:
            result.append(ch)
    return "".join(result)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = autokey_encrypt(text, "H")
    decrypted = autokey_decrypt(encrypted, "H")
    return {"algorithm": "Autokey", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Playfair
def playfair_build_grid(key):
    key = "".join(ch for ch in key.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").replace("J", "I")
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    grid = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    pos = {ch: (r, c) for r, row in enumerate(grid) for c, ch in enumerate(row)}
    return grid, pos

def playfair_prepare_digraphs(plaintext):
    letters = "".join(ch for ch in plaintext.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").replace("J", "I")
    i, digraphs = 0, []
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else "X"
        if a == b:
            digraphs.append(a + ("Q" if a == "X" else "X"))
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if digraphs and len(digraphs[-1]) == 1:
        digraphs[-1] += "X"
    return digraphs

def playfair_encrypt(plaintext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for a, b in playfair_prepare_digraphs(plaintext):
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca + 1) % 5] + grid[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(grid[(ra + 1) % 5][ca] + grid[(rb + 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)

def playfair_decrypt(ciphertext, key):
    grid, pos = playfair_build_grid(key)
    out = []
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(grid[ra][(ca - 1) % 5] + grid[rb][(cb - 1) % 5])
        elif ca == cb:
            out.append(grid[(ra - 1) % 5][ca] + grid[(rb - 1) % 5][cb])
        else:
            out.append(grid[ra][cb] + grid[rb][ca])
    return "".join(out)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = playfair_encrypt(text, "GUIDANCE")
    decrypted = playfair_decrypt(encrypted, "GUIDANCE")
    return {"algorithm": "Playfair", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Hill
def hill_mat_inverse_2x2(matrix, modulus=26):
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % modulus
    det_inv = pow(det, -1, modulus)
    return [
        [(d * det_inv) % modulus, (-b * det_inv) % modulus],
        [(-c * det_inv) % modulus, (a * det_inv) % modulus],
    ]

def hill_prepare(plaintext):
    letters = "".join(ch for ch in plaintext.upper() if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    if len(letters) % 2 != 0:
        letters += "X"
    return letters

def hill_encrypt(plaintext, key_matrix):
    letters = hill_prepare(plaintext)
    out = []
    for i in range(0, len(letters), 2):
        p1, p2 = ord(letters[i]) - ord('A'), ord(letters[i + 1]) - ord('A')
        c1 = (key_matrix[0][0] * p1 + key_matrix[0][1] * p2) % 26
        c2 = (key_matrix[1][0] * p1 + key_matrix[1][1] * p2) % 26
        out.append(chr(c1 + ord('A')))
        out.append(chr(c2 + ord('A')))
    return "".join(out)

def hill_decrypt(ciphertext, key_matrix):
    inv = hill_mat_inverse_2x2(key_matrix)
    out = []
    for i in range(0, len(ciphertext), 2):
        c1, c2 = ord(ciphertext[i]) - ord('A'), ord(ciphertext[i + 1]) - ord('A')
        p1 = (inv[0][0] * c1 + inv[0][1] * c2) % 26
        p2 = (inv[1][0] * c1 + inv[1][1] * c2) % 26
        out.append(chr(p1 + ord('A')))
        out.append(chr(p2 + ord('A')))
    return "".join(out)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = hill_encrypt(text, [[3, 3], [2, 7]])
    decrypted = hill_decrypt(encrypted, [[3, 3], [2, 7]])
    return {"algorithm": "Hill", "ciphertext": encrypted, "decrypted_text": decrypted}

# template: Transposition
def transposition_key_order(key):
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def transposition_encrypt(plaintext, key):
    cols = len(key)
    padded = plaintext + "X" * (-len(plaintext) % cols)
    rows = [padded[i:i + cols] for i in range(0, len(padded), cols)]
    order = transposition_key_order(key)
    return "".join("".join(row[c] for row in rows) for c in order)

def transposition_decrypt(ciphertext, key):
    cols = len(key)
    rows_count = len(ciphertext) // cols
    order = transposition_key_order(key)
    col_texts = [ciphertext[i * rows_count:(i + 1) * rows_count] for i in range(cols)]
    columns = [None] * cols
    for i, original_col in enumerate(order):
        columns[original_col] = col_texts[i]
    rows = ["".join(columns[c][r] for c in range(cols)) for r in range(rows_count)]
    return "".join(rows)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = transposition_encrypt(text, "ZEBRA")
    decrypted = transposition_decrypt(encrypted, "ZEBRA")
    return {"algorithm": "Transposition", "ciphertext": encrypted, "decrypted_text": decrypted}
