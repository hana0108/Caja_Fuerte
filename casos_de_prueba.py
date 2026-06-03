import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from caja_fuerte import (
    sha256,
    aes_cifrar, aes_descifrar,
    chacha_cifrar, chacha_descifrar,
    rsa_claves, rsa_cifrar, rsa_descifrar,
    firmar, verificar,
)

ok = 0
fail = 0

def check(nombre, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  [PASS] {nombre}")
    else:
        fail += 1
        print(f"  [FAIL] {nombre}")
    if extra:
        print(f"         {extra}")


priv, pub = rsa_claves()


# caso 1: flujo normal
print("\n--- 1. flujo normal ---")
msg = b"mensaje de prueba"
c_aes = os.urandom(32); n_aes = os.urandom(12)
ct, tag = aes_cifrar(msg, c_aes, n_aes)
pt = aes_descifrar(ct, c_aes, n_aes, tag)

c_cha = os.urandom(32); n_cha = os.urandom(12)
ct2 = chacha_cifrar(msg, c_cha, n_cha)
pt2 = chacha_descifrar(ct2, c_cha, n_cha)

firma = firmar(msg, priv)

check("AES descifra bien",       pt == msg)
check("ChaCha20 descifra bien",  pt2 == msg)
check("firma valida",            verificar(msg, firma, pub))
check("hashes coinciden",        sha256(msg) == sha256(pt))


# caso 2: mensaje largo
print("\n--- 2. mensaje largo ---")
msg_l = b"texto de prueba largo " * 30
c2 = os.urandom(32); n2 = os.urandom(12)
ct_l, tag_l = aes_cifrar(msg_l, c2, n2)
pt_l = aes_descifrar(ct_l, c2, n2, tag_l)

c2c = os.urandom(32); n2c = os.urandom(12)
ct_l2 = chacha_cifrar(msg_l, c2c, n2c)
pt_l2 = chacha_descifrar(ct_l2, c2c, n2c)

check("AES con mensaje largo",       pt_l == msg_l)
check("ChaCha20 con mensaje largo",  pt_l2 == msg_l)


# caso 3: unicode
print("\n--- 3. unicode ---")
msg_u = "contraseña: ñoño 密码 🔐".encode("utf-8")
c3 = os.urandom(32); n3 = os.urandom(12)
ct_u, tag_u = aes_cifrar(msg_u, c3, n3)
pt_u = aes_descifrar(ct_u, c3, n3, tag_u)

check("AES preserva unicode",  pt_u == msg_u)


# caso 4: clave AES incorrecta
print("\n--- 4. clave incorrecta en AES ---")
c_ok = os.urandom(32); n4 = os.urandom(12)
ct4, tag4 = aes_cifrar(b"secreto", c_ok, n4)

error = False
try:
    aes_descifrar(ct4, os.urandom(32), n4, tag4)
except Exception:
    error = True

check("AES rechaza clave incorrecta",  error)


# caso 5: firma con clave ajena
print("\n--- 5. firma invalida ---")
priv_b, pub_b = rsa_claves()
firma5 = firmar(b"hola", priv)

check("firma ok con clave correcta",   verificar(b"hola", firma5, pub))
check("firma falla con clave ajena",   not verificar(b"hola", firma5, pub_b))
check("firma falla si cambia mensaje", not verificar(b"hola2", firma5, pub))


# caso 6: encapsulado RSA
print("\n--- 6. encapsulado RSA ---")
clave_orig = os.urandom(32)
clave_enc = rsa_cifrar(clave_orig, pub)
clave_rec = rsa_descifrar(clave_enc, priv)

check("clave recuperada correctamente",  clave_orig == clave_rec)
check("clave cifrada es distinta",       clave_enc != clave_orig)


# caso 7: efecto avalancha sha256
print("\n--- 7. efecto avalancha SHA-256 ---")
h1 = sha256(b"mensaje A")
h2 = sha256(b"mensaje B")
h3 = sha256(b"mensaje A")

bits = sum(bin(int(a,16) ^ int(b,16)).count("1") for a,b in zip(h1,h2))

check("hashes distintos para inputs distintos",  h1 != h2)
check("mismo input siempre da el mismo hash",    h1 == h3)
check(f"avalancha: {bits}/256 bits cambian",     bits > 80,
      f"{bits/256*100:.1f}% de bits distintos")


# caso 8: mensaje vacio
print("\n--- 8. mensaje vacio ---")
c8 = os.urandom(32); n8 = os.urandom(12)
ct8, tag8 = aes_cifrar(b"", c8, n8)
pt8 = aes_descifrar(ct8, c8, n8, tag8)
firma8 = firmar(b"", priv)

check("AES acepta mensaje vacio",           pt8 == b"")
check("firma valida sobre mensaje vacio",   verificar(b"", firma8, pub))


# resumen
print(f"\n{'='*40}")
print(f"  {ok}/{ok+fail} casos pasaron", end="")
if fail:
    print(f"  ({fail} fallaron)")
else:
    print()
print(f"{'='*40}\n")

sys.exit(0 if fail == 0 else 1)