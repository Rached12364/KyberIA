"""
Détecteur de fuites de temps par IA.

Principe (attaque par canal auxiliaire) :
  Un pirate envoie à Bob des chiffrés légèrement modifiés et mesure le temps de réponse.
  Si ce temps dépend d'une information secrète, il peut, essai après essai, reconstruire la clé.

Ici l'information secrète est : « le message déchiffré a-t-il changé ? ».
  - Avec la comparaison NAÏVE, la vérification s'arrête à la première différence :
      message inchangé -> la différence est à la fin -> vérification LONGUE
      message changé   -> tout diffère dès le début -> vérification COURTE
  - Avec la comparaison à TEMPS CONSTANT, le temps est toujours le même.

L'IA (forêt aléatoire) reçoit seulement les temps mesurés et essaie de deviner cette
information secrète. Si elle y arrive nettement mieux que le hasard (50 %), il y a une fuite.
"""
import random
import numpy as np
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from kyber import Kyber, compare_naive, compare_constant_time

IMPLEMENTATIONS = {
    "Naïve (s'arrête à la 1re différence)": compare_naive,
    "Temps constant (version corrigée)": compare_constant_time,
}


def _tampered_ciphertext(kb, ek, dk):
    """Chiffré valide puis 1 bit modifié dans la 2e partie (v). Renvoie (chiffré, secret)."""
    k = kb.k
    dk_pke = dk[:384 * k]
    _, c = kb.encaps(ek)
    m = kb.pke_decrypt(dk_pke, c)
    b = bytearray(c)
    pos = random.randrange(32 * kb.du * k, len(c))
    b[pos] ^= 1 << random.choice([0, 3, 4, 7])        # bit faible (souvent sans effet) ou fort (change le message)
    b = bytes(b)
    secret = int(kb.pke_decrypt(dk_pke, b) != m)      # 1 = le message déchiffré a changé
    return b, secret


def collect(compare, n_traces=300, repeats=5, jitter_us=0.0, kb=None, progress=None):
    """Mesure n_traces chiffrés modifiés. Chaque trace = `repeats` mesures du temps de vérification (µs)."""
    kb = kb or Kyber("ML-KEM-512")
    ek, dk = kb.keygen()
    traces, labels = [], []
    for i in range(n_traces):
        c, secret = _tampered_ciphertext(kb, ek, dk)
        probe = []
        for _ in range(repeats):
            kb.decaps(dk, c, compare, probe)
        t = np.array(probe) / 1000.0
        if jitter_us:
            t = t + np.abs(np.random.normal(0, jitter_us, size=t.shape))   # bruit de mesure (réseau, système…)
        traces.append(t)
        labels.append(secret)
        if progress and i % 10 == 0:
            progress(i / n_traces)
    return np.array(traces), np.array(labels)


def features(traces):
    return np.column_stack([traces.min(1), np.median(traces, 1), traces.mean(1), traces.std(1)])


def analyze(traces, labels, seed=0):
    """Entraîne l'IA sur 70 % des mesures, la teste sur les 30 % restants."""
    X = features(traces)
    Xa, Xb, ya, yb = train_test_split(X, labels, test_size=0.3, stratify=labels, random_state=seed)
    clf = RandomForestClassifier(n_estimators=200, random_state=seed).fit(Xa, ya)
    acc = clf.score(Xb, yb)
    correct = int(round(acc * len(yb)))
    chance = max(yb.mean(), 1 - yb.mean())                       # score d'un devin qui répond toujours pareil
    p_value = stats.binomtest(correct, len(yb), chance, alternative="greater").pvalue
    t_stat = stats.ttest_ind(X[labels == 0, 0], X[labels == 1, 0], equal_var=False).statistic   # test classique (TVLA)
    leak = bool(p_value < 0.01 and acc > chance + 0.05)
    return dict(accuracy=acc, chance=chance, p_value=p_value, t_stat=float(t_stat), leak=leak, n_test=len(yb))


if __name__ == "__main__":
    for name, cmp in IMPLEMENTATIONS.items():
        tr, lb = collect(cmp, n_traces=300)
        r = analyze(tr, lb)
        verdict = "FUITE DÉTECTÉE" if r["leak"] else "aucune fuite détectée"
        print(f"{name:40s} précision IA {100*r['accuracy']:5.1f} %  (hasard {100*r['chance']:.0f} %)  "
              f"t = {r['t_stat']:7.1f}  ->  {verdict}")
