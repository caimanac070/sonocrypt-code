import sys, os, wave, hashlib, functools
import numpy as np

FS, F0, DF, M = 44100, 1500, 200, 16          
PRE = [0, 15, 0, 15, 0, 15, 3, 12]            
SALT = b"sonocrypt-v1"

def crc8(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

@functools.lru_cache(maxsize=None)
def key_from(pw):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), SALT, 100000, 32)

def encrypt(msg, pw):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(12)
    e = Cipher(algorithms.AES(key_from(pw)), modes.GCM(iv)).encryptor()
    ct = e.update(msg) + e.finalize()
    return iv + ct + e.tag[:8]                 

def decrypt(blob, pw):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
    if len(blob) < 20: return None
    iv, ct, tag = blob[:12], blob[12:-8], blob[-8:]
    d = Cipher(algorithms.AES(key_from(pw)), modes.GCM(iv, tag, min_tag_length=8)).decryptor()
    try: return d.update(ct) + d.finalize()
    except InvalidTag: return None

def frame(payload, enc):
    data = bytes([enc, len(payload)]) + payload
    data += bytes([crc8(data)])
    return PRE + [n for b in data for n in (b >> 4, b & 15)]

def modulate(sym, T=0.08, pad=0.3):
    n = int(round(T * FS))
    f = np.repeat(F0 + DF * np.array(sym), n)
    x = 0.5 * np.sin(2 * np.pi * np.cumsum(f) / FS)   
    k = int(0.005 * FS); w = np.ones(len(x))
    w[:k] = np.linspace(0, 1, k); w[-k:] = np.linspace(1, 0, k)
    z = np.zeros(int(pad * FS))
    return np.concatenate([z, x * w, z])

def demodulate(x, T=0.08):
    W = int(round(T * FS)); hop = W // 4
    if len(x) < W + hop: return []
    n = np.arange(W)
    E = np.exp(-2j * np.pi * (F0 + DF * np.arange(M))[None, :] * n[:, None] / FS)
    fr = np.lib.stride_tricks.sliding_window_view(x, W)[::hop]
    d = np.argmax(np.abs(fr @ E), axis=1)             
    out = {}
    for p in range(4):                                
        s = [int(v) for v in d[p::4]]
        for i in range(len(s) - len(PRE) - 4):
            if s[i:i + len(PRE)] != PRE: continue
            r = s[i + len(PRE):]
            by = lambda k: (r[2 * k] << 4) | r[2 * k + 1]
            enc, L = by(0), by(1)
            if enc > 1 or len(r) < 2 * (L + 3): continue
            data = bytes(by(k) for k in range(L + 2))
            if crc8(data) == by(L + 2): out[data[2:]] = enc
    return [(e, p) for p, e in out.items()]

def send(text, pw=None, T=0.08):
    m = text.encode()
    return modulate(frame(encrypt(m, pw) if pw else m, 1 if pw else 0), T)

def receive(x, pw=None, T=0.08):
    for enc, p in demodulate(x, T):
        if enc == 0: return p.decode(errors="replace")
        if pw:
            m = decrypt(p, pw)
            if m is not None: return m.decode(errors="replace")
    return None

def awgn(x, snr_db, rng):
    sig = 0.5 ** 2 / 2
    return x + rng.normal(0, np.sqrt(sig / 10 ** (snr_db / 10)), len(x))

def echo(x, delay=0.04, g=0.6):
    d = int(delay * FS); y = x.copy(); y[d:] += g * x[:-d]; return y

def bench(trials=40, seed=1):
    rng = np.random.default_rng(seed); pw = "clave-demo"
    rnd = lambda: "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789 "), 16))
    def run(snr, T, key, ech=False):
        ok = 0
        for _ in range(trials):
            m = rnd(); x = send(m, key, T)
            x = np.concatenate([np.zeros(int(rng.integers(0, 20000))), x])
            if ech: x = echo(x)
            ok += receive(awgn(x, snr, rng), key, T) == m
        return 100 * ok / trials
    print("SNR(dB)  plano  cifrado  eco+cifrado   [T=80 ms, % exito]")
    for snr in (10, 0, -5, -10, -15, -20):
        print(f"{snr:6d} {run(snr,.08,None):6.0f} {run(snr,.08,pw):8.0f} {run(snr,.08,pw,True):12.0f}")
    print("\nT(ms)  bps_brutos  dur_16B_cifrado(s)  exito@-10dB  exito@-15dB")
    for T in (0.04, 0.06, 0.08, 0.12):
        n = len(frame(bytes(36), 1)) * T
        print(f"{int(T*1000):5d} {4/T:11.0f} {n:19.2f} {run(-10,T,pw):12.0f} {run(-15,T,pw):12.0f}")
    x = send("mensaje secreto", pw); r = sum(receive(awgn(x, 0, rng), "otra", .08) is not None for _ in range(trials))
    print(f"\nClave incorrecta: {r}/{trials} mensajes aceptados (esperado 0)")

def wr(name, x):
    with wave.open(name, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(FS)
        w.writeframes((x * 32767).astype("<i2").tobytes())

def rd(name):
    with wave.open(name) as w:
        return np.frombuffer(w.readframes(w.getnframes()), "<i2").astype(float) / 32767

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["send"]: wr("mensaje.wav", send(a[1], a[2] if len(a) > 2 else None)); print("mensaje.wav listo")
    elif a[:1] == ["recv"]: print(receive(rd(a[1]), a[2] if len(a) > 2 else None))
    elif a[:1] == ["bench"]: bench()
    else: print(__doc__)
