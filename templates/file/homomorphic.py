# Source fragments for generate_solution.py; do not run this file directly.

# template: Paillier
def encrypt_homomorphic_paillier(m):
    p = 17
    q = 19
    n = p * q
    n2 = n * n
    g = n + 1
    lam = (p - 1) * (q - 1)
    mu = pow(lam, -1, n)
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c,n2

def decrypt_homomorphic_paillier(c):
    p = 17
    q = 19
    n = p * q
    n2 = n * n
    g = n + 1
    lam = (p - 1) * (q - 1)
    mu = pow(lam, -1, n)
    u = pow(c, lam, n2)
    L = (u - 1) // n
    m = (L * mu) % n
    return m

def expected_homomorphic(a, b):
    return (a + b) % 323


def calculate_homomorphic(a, b):
    if not (0 <= a < 323 and 0 <= b < 323):
        raise ValueError("Use integers from 0 to 322")
    c1, modulus = encrypt_homomorphic_paillier(a)
    c2, modulus = encrypt_homomorphic_paillier(b)
    return {"operation": "addition modulo 323", "ciphertext": c1 * c2 % modulus}


def decrypt_homomorphic(ciphertext):
    return decrypt_homomorphic_paillier(ciphertext)

# template: RSA
def encrypt_homomorphic_RSA(m):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    # print("Public key:", (e, n))
    # print("Private key:", (d, n))
    return pow(m, e, n),n

def decrypt_homomorphic_RSA(c):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    return pow(c, d, n)

def expected_homomorphic(a, b):
    return (a * b) % 143


def calculate_homomorphic(a, b):
    if not (0 <= a < 143 and 0 <= b < 143):
        raise ValueError("Use integers from 0 to 142")
    c1, modulus = encrypt_homomorphic_RSA(a)
    c2, modulus = encrypt_homomorphic_RSA(b)
    return {"operation": "multiplication modulo 143", "ciphertext": c1 * c2 % modulus}


def decrypt_homomorphic(ciphertext):
    return decrypt_homomorphic_RSA(ciphertext)

# template: ElGamal
HOM_P, HOM_G, HOM_X = 467, 2, 127
HOM_Y = pow(HOM_G, HOM_X, HOM_P)


def encrypt_homomorphic_elgamal(m):
    k = secrets.randbelow(HOM_P - 2) + 1
    return pow(HOM_G, k, HOM_P), m * pow(HOM_Y, k, HOM_P) % HOM_P


def decrypt_homomorphic(ciphertext):
    a, b = ciphertext
    return b * pow(pow(a, HOM_X, HOM_P), -1, HOM_P) % HOM_P


def expected_homomorphic(a, b):
    return a * b % HOM_P


def calculate_homomorphic(a, b):
    if not (1 <= a < HOM_P and 1 <= b < HOM_P):
        raise ValueError("Use integers from 1 to 466")
    c1, c2 = encrypt_homomorphic_elgamal(a), encrypt_homomorphic_elgamal(b)
    combined = [c1[0] * c2[0] % HOM_P, c1[1] * c2[1] % HOM_P]
    return {"operation": "multiplication modulo 467", "ciphertext": combined}
