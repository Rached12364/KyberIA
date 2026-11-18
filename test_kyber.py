"""Vérifie notre Kyber contre l'implémentation de référence kyber-py (pip install kyber-py)."""
import os, time
from kyber import Kyber, compare_naive

def check(name):
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    ref = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}[name]
    kb = Kyber(name)
    for _ in range(3):
        d, z, m = os.urandom(32), os.urandom(32), os.urandom(32)
        ek, dk = kb.keygen(d, z); ek_r, dk_r = ref._keygen_internal(d, z)
        assert ek == ek_r and dk == dk_r, "keygen"
        K, c = kb.encaps(ek, m); K_r, c_r = ref._encaps_internal(ek, m)
        assert K == K_r and c == c_r, "encaps"
        assert kb.decaps(dk, c) == K == ref._decaps_internal(dk, c), "decaps"
        bad = bytearray(c); bad[5] ^= 1; bad = bytes(bad)
        assert kb.decaps(dk, bad) == ref._decaps_internal(dk, bad) != K, "rejet implicite"
        assert kb.decaps(dk, bad, compare_naive) == kb.decaps(dk, bad)
    print(name, "identique à la référence ✓")

if __name__ == "__main__":
    for n in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"): check(n)
    kb = Kyber(); ek, dk = kb.keygen(); t = time.perf_counter(); K, c = kb.encaps(ek)
    print(f"encaps {1000*(time.perf_counter()-t):.1f} ms"); t = time.perf_counter(); kb.decaps(dk, c); print(f"decaps {1000*(time.perf_counter()-t):.1f} ms")
