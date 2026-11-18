"""
Kyber (ML-KEM, standard NIST FIPS 203) écrit à partir de zéro en Python.

Idée générale :
  - Bob crée une clé publique (ek) et une clé secrète (dk).
  - Alice utilise ek pour fabriquer un secret partagé K et un "chiffré" c.
  - Bob utilise dk et c pour retrouver le même secret K.
  - Un pirate qui voit ek et c ne peut pas retrouver K, même avec un ordinateur quantique.

La sécurité vient d'un problème mathématique difficile : retrouver un secret
caché sous du "bruit" dans un réseau euclidien (Module-LWE).
"""
import hashlib
import hmac
import os
import time

Q = 3329          # module : tous les calculs se font modulo 3329
N = 256           # chaque polynôme a 256 coefficients
ZETA = 17         # racine 256-ième de l'unité modulo Q (pour la NTT)

PARAMS = {        # k = taille de la matrice, eta = force du bruit, du/dv = compression
    "ML-KEM-512":  dict(k=2, eta1=3, eta2=2, du=10, dv=4),
    "ML-KEM-768":  dict(k=3, eta1=2, eta2=2, du=10, dv=4),
    "ML-KEM-1024": dict(k=4, eta1=2, eta2=2, du=11, dv=5),
}

# ---------------------------------------------------------------- hachage (SHA-3)
def H(s):  return hashlib.sha3_256(s).digest()
def J(s):  return hashlib.shake_256(s).digest(32)
def G(s):
    h = hashlib.sha3_512(s).digest()
    return h[:32], h[32:]
def PRF(eta, s, b): return hashlib.shake_256(s + bytes([b])).digest(64 * eta)

# ---------------------------------------------------------------- NTT
def _bitrev7(i): return int(f"{i:07b}"[::-1], 2)
ZETAS = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]

def ntt(f):
    """Transformée NTT : rend la multiplication de polynômes très rapide."""
    f = list(f); i = 1; length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            z = ZETAS[i]; i += 1
            for j in range(start, start + length):
                t = z * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f

def ntt_inv(f):
    f = list(f); i = 127; length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            z = ZETAS[i]; i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]          # 3303 = 128^-1 mod Q

def ntt_mul(a, b):
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1, g = a[2*i], a[2*i+1], b[2*i], b[2*i+1], GAMMAS[i]
        h[2*i] = (a0 * b0 + a1 * b1 * g) % Q
        h[2*i+1] = (a0 * b1 + a1 * b0) % Q
    return h

def padd(a, b): return [(x + y) % Q for x, y in zip(a, b)]
def psub(a, b): return [(x - y) % Q for x, y in zip(a, b)]

# ---------------------------------------------------------------- encodage / compression
def byte_encode(f, d):
    m = (1 << d) if d < 12 else Q
    bits = 0; nb = 0; out = bytearray()
    for a in f:
        bits |= (a % m) << nb; nb += d
        while nb >= 8:
            out.append(bits & 255); bits >>= 8; nb -= 8
    return bytes(out)

def byte_decode(B, d):
    m = (1 << d) if d < 12 else Q
    x = int.from_bytes(B, "little")
    return [((x >> (d * i)) & ((1 << d) - 1)) % m for i in range(N)]

def compress(f, d):   return [((x << d) + Q // 2) // Q % (1 << d) for x in f]
def decompress(f, d): return [(Q * y + (1 << (d - 1))) >> d for y in f]

# ---------------------------------------------------------------- échantillonnage
def sample_ntt(seed):
    """Coefficients uniformes de la matrice publique A (rejet des valeurs >= Q)."""
    xof = hashlib.shake_128(seed).digest(840)
    a, j, pos = [], 0, 0
    while len(a) < N:
        if pos + 3 > len(xof):
            xof = hashlib.shake_128(seed).digest(len(xof) * 2)
        c0, c1, c2 = xof[pos], xof[pos+1], xof[pos+2]; pos += 3
        d1 = c0 + 256 * (c1 % 16); d2 = (c1 // 16) + 16 * c2
        if d1 < Q: a.append(d1)
        if d2 < Q and len(a) < N: a.append(d2)
    return a

def sample_cbd(B, eta):
    """Bruit : petits nombres entre -eta et +eta (loi binomiale centrée)."""
    bits = int.from_bytes(B, "little")
    f = []
    for i in range(N):
        x = sum((bits >> (2 * i * eta + j)) & 1 for j in range(eta))
        y = sum((bits >> (2 * i * eta + eta + j)) & 1 for j in range(eta))
        f.append((x - y) % Q)
    return f

# ---------------------------------------------------------------- K-PKE (chiffrement à clé publique)
class Kyber:
    def __init__(self, name="ML-KEM-512"):
        self.name = name
        p = PARAMS[name]
        self.k, self.eta1, self.eta2, self.du, self.dv = p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]

    def _matrix(self, rho):
        return [[sample_ntt(rho + bytes([j, i])) for j in range(self.k)] for i in range(self.k)]

    def pke_keygen(self, d):
        k = self.k
        rho, sigma = G(d + bytes([k]))
        A = self._matrix(rho)
        s = [ntt(sample_cbd(PRF(self.eta1, sigma, i), self.eta1)) for i in range(k)]
        e = [ntt(sample_cbd(PRF(self.eta1, sigma, k + i), self.eta1)) for i in range(k)]
        t = []
        for i in range(k):
            acc = e[i]
            for j in range(k): acc = padd(acc, ntt_mul(A[i][j], s[j]))
            t.append(acc)                                    # t = A·s + e   (le secret s est caché par le bruit e)
        ek = b"".join(byte_encode(ti, 12) for ti in t) + rho
        dk = b"".join(byte_encode(si, 12) for si in s)
        return ek, dk

    def pke_encrypt(self, ek, m, r):
        k = self.k
        t = [byte_decode(ek[384*i:384*(i+1)], 12) for i in range(k)]
        rho = ek[384*k:]
        A = self._matrix(rho)
        y = [ntt(sample_cbd(PRF(self.eta1, r, i), self.eta1)) for i in range(k)]
        e1 = [sample_cbd(PRF(self.eta2, r, k + i), self.eta2) for i in range(k)]
        e2 = sample_cbd(PRF(self.eta2, r, 2 * k), self.eta2)
        u = []
        for j in range(k):
            acc = [0] * N
            for i in range(k): acc = padd(acc, ntt_mul(A[i][j], y[i]))
            u.append(padd(ntt_inv(acc), e1[j]))              # u = Aᵀ·y + e1
        mu = decompress(byte_decode(m, 1), 1)                # chaque bit du message -> 0 ou Q/2
        acc = [0] * N
        for i in range(k): acc = padd(acc, ntt_mul(t[i], y[i]))
        v = padd(padd(ntt_inv(acc), e2), mu)                 # v = tᵀ·y + e2 + message
        c1 = b"".join(byte_encode(compress(ui, self.du), self.du) for ui in u)
        c2 = byte_encode(compress(v, self.dv), self.dv)
        return c1 + c2

    def pke_decrypt(self, dk, c):
        k = self.k
        u = [decompress(byte_decode(c[32*self.du*i:32*self.du*(i+1)], self.du), self.du) for i in range(k)]
        v = decompress(byte_decode(c[32*self.du*k:], self.dv), self.dv)
        s = [byte_decode(dk[384*i:384*(i+1)], 12) for i in range(k)]
        acc = [0] * N
        for i in range(k): acc = padd(acc, ntt_mul(s[i], ntt(u[i])))
        w = psub(v, ntt_inv(acc))                            # w = message + petit bruit
        return byte_encode(compress(w, 1), 1)                # arrondi : proche de Q/2 -> 1, proche de 0 -> 0

    # ------------------------------------------------------------ ML-KEM (échange de clé)
    def keygen(self, d=None, z=None):
        d = d or os.urandom(32); z = z or os.urandom(32)
        ek, dk_pke = self.pke_keygen(d)
        dk = dk_pke + ek + H(ek) + z
        return ek, dk

    def encaps(self, ek, m=None):
        m = m or os.urandom(32)
        K, r = G(m + H(ek))
        c = self.pke_encrypt(ek, m, r)
        return K, c

    def decaps(self, dk, c, compare=None, probe=None):
        """compare : fonction de comparaison des chiffrés (temps constant par défaut).
        probe : si c'est une liste, on y ajoute le temps (ns) de l'étape de vérification,
                comme le ferait une sonde de mesure (analyse de canal auxiliaire)."""
        compare = compare or compare_constant_time
        k = self.k
        dk_pke = dk[:384*k]; ek = dk[384*k:768*k+32]; h = dk[768*k+32:768*k+64]; z = dk[768*k+64:]
        m2 = self.pke_decrypt(dk_pke, c)
        K2, r2 = G(m2 + h)
        Kbar = J(z + c)
        c2 = self.pke_encrypt(ek, m2, r2)                    # on rechiffre pour vérifier le chiffré reçu
        if probe is None:
            ok = compare(c, c2)
        else:
            t0 = time.perf_counter_ns(); ok = compare(c, c2); probe.append(time.perf_counter_ns() - t0)
        return K2 if ok else Kbar                            # si c a été trafiqué : clé aléatoire

# ---------------------------------------------------------------- comparaisons (le point sensible)
def compare_constant_time(a, b):
    """Bonne version : le temps ne dépend pas de l'endroit où a et b diffèrent."""
    if len(a) != len(b): return False
    diff = 0
    for x, y in zip(a, b): diff |= x ^ y
    return diff == 0

def compare_naive(a, b):
    """Mauvaise version (volontaire) : s'arrête à la première différence -> fuite de temps."""
    if len(a) != len(b): return False
    for x, y in zip(a, b):
        if x != y: return False
    return True
