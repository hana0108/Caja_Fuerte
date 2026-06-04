import os
import time
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox, font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


#  Utilidades 

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def tiempo(fn, *args, **kwargs):
    t = time.perf_counter()
    res = fn(*args, **kwargs)
    ms = (time.perf_counter() - t) * 1000
    return res, ms


#  AES-256-GCM 

def aes_cifrar(msg, clave, nonce):
    enc = Cipher(algorithms.AES(clave), modes.GCM(nonce)).encryptor()
    ct = enc.update(msg) + enc.finalize()
    return ct, enc.tag

def aes_descifrar(ct, clave, nonce, tag):
    dec = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag)).decryptor()
    return dec.update(ct) + dec.finalize()


#  ChaCha20-Poly1305 

def chacha_cifrar(msg, clave, nonce):
    return ChaCha20Poly1305(clave).encrypt(nonce, msg, None)

def chacha_descifrar(ct, clave, nonce):
    return ChaCha20Poly1305(clave).decrypt(nonce, ct, None)


# RSA-3072 

def rsa_claves():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return priv, priv.public_key()

def rsa_cifrar(clave, pub):
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    return pub.encrypt(clave, oaep)

def rsa_descifrar(ct, priv):
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    return priv.decrypt(ct, oaep)


# Firma digital 

def firmar(msg, priv):
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    return priv.sign(msg, pss, hashes.SHA256())

def verificar(msg, firma, pub):
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    try:
        pub.verify(firma, msg, pss, hashes.SHA256())
        return True
    except Exception:
        return False


#  Logica principal

def procesar(mensaje_str, simular_alteracion=False):
    msg = mensaje_str.encode("utf-8")
    resultado = {}

    resultado["hash_original"] = sha256(msg)

    (priv, pub), ms_keygen = tiempo(rsa_claves)
    resultado["ms_keygen"] = ms_keygen

    clave_aes = os.urandom(32)
    nonce_aes = os.urandom(12)
    (ct_aes, tag_aes), ms_aes_enc = tiempo(aes_cifrar, msg, clave_aes, nonce_aes)
    resultado["ct_aes"] = ct_aes.hex()[:48] + "..."
    resultado["ms_aes_enc"] = ms_aes_enc

    clave_cha = os.urandom(32)
    nonce_cha = os.urandom(12)
    ct_cha, ms_cha_enc = tiempo(chacha_cifrar, msg, clave_cha, nonce_cha)
    resultado["ct_cha"] = ct_cha.hex()[:48] + "..."
    resultado["ms_cha_enc"] = ms_cha_enc

    clave_enc, ms_rsa = tiempo(rsa_cifrar, clave_aes, pub)
    resultado["ms_rsa"] = ms_rsa

    firma, ms_firma = tiempo(firmar, msg, priv)
    resultado["ms_firma"] = ms_firma

    # Simular alteracion: corromper la firma despues de generarla
    if simular_alteracion:
        firma_bytes = bytearray(firma)
        firma_bytes[0] ^= 0xFF  # invertir el primer byte
        firma = bytes(firma_bytes)

    clave_rec = rsa_descifrar(clave_enc, priv)
    pt_aes, ms_aes_dec = tiempo(aes_descifrar, ct_aes, clave_rec, nonce_aes, tag_aes)
    pt_cha, ms_cha_dec = tiempo(chacha_descifrar, ct_cha, clave_cha, nonce_cha)
    resultado["ms_aes_dec"] = ms_aes_dec
    resultado["ms_cha_dec"] = ms_cha_dec

    resultado["mensaje_rec"] = pt_aes.decode("utf-8")
    resultado["firma_ok"] = verificar(msg, firma, pub)
    resultado["hash_rec"] = sha256(pt_aes)
    resultado["hashes_ok"] = resultado["hash_original"] == resultado["hash_rec"]

    return resultado


#  Paleta de colores

BG_VENTANA  = "#F5F0E8"   # crema claro (fondo principal)
BG_CAJA     = "#FDFAF4"   # crema casi blanco (cuadro de salida)
BG_ENTRADA  = "#FFFFFF"   # blanco (campo de texto)
COLOR_MARRON      = "#6B4C2A"   # marron oscuro (acento principal)
COLOR_MARRON_MED  = "#8B6340"   # marron medio (bordes, secundario)
COLOR_MARRON_SUAVE= "#B89470"   # marron suave (placeholder, subtitulo)
COLOR_TEXTO       = "#2C1F12"   # casi negro calido (texto principal)
COLOR_VERDE       = "#2E6B3E"   # verde bosque (exito)
COLOR_ROJO        = "#9B2335"   # rojo oscuro (error)
COLOR_SEPARADOR   = "#D4C4A8"   # crema oscuro (lineas separadoras)

# Fuentes preferidas con fallback
FONT_TITULO  = ("Segoe UI", 15, "bold")
FONT_SUBTIT  = ("Segoe UI", 9)
FONT_LABEL   = ("Segoe UI", 10)
FONT_LABEL_B = ("Segoe UI", 10, "bold")
FONT_BTN     = ("Segoe UI", 10, "bold")
FONT_MONO    = ("Consolas", 9)     # resultados monoespacio
FONT_ESTADO  = ("Segoe UI", 10, "bold")


#  Interfaz grafica 

def lanzar_gui():
    ventana = tk.Tk()
    ventana.title("Gestión de contraseñas - Transmision Hibrida")
    ventana.configure(bg=BG_VENTANA)
    ventana.geometry("760x700")
    ventana.resizable(True, True)

    # Cabecera 
    frame_cabecera = tk.Frame(ventana, bg=BG_VENTANA)
    frame_cabecera.pack(fill="x", padx=28, pady=(20, 0))

    tk.Label(
        frame_cabecera,
        text="GESTOR DE CONTRASEÑAS",
        font=("Segoe UI", 17, "bold"),
        bg=BG_VENTANA, fg=COLOR_MARRON
    ).pack(anchor="w")

    tk.Label(
        frame_cabecera,
        text="Transmision Hibrida  |  AES-256-GCM  ·  ChaCha20-Poly1305  ·  RSA-3072  ·  SHA-256",
        font=FONT_SUBTIT,
        bg=BG_VENTANA, fg=COLOR_MARRON_SUAVE
    ).pack(anchor="w", pady=(2, 0))

    # Separador decorativo
    tk.Frame(ventana, height=1, bg=COLOR_SEPARADOR).pack(fill="x", padx=28, pady=(10, 0))

    #  Entrada
    frame_entrada = tk.Frame(ventana, bg=BG_VENTANA)
    frame_entrada.pack(fill="x", padx=28, pady=(14, 0))

    tk.Label(
        frame_entrada,
        text="Contraseña a proteger",
        font=FONT_LABEL_B,
        bg=BG_VENTANA, fg=COLOR_TEXTO
    ).pack(anchor="w")

    campo_msg = tk.Entry(
        frame_entrada,
        font=("Segoe UI", 11),
        bg=BG_ENTRADA, fg=COLOR_TEXTO,
        insertbackground=COLOR_MARRON,
        relief="flat", bd=0,
        highlightthickness=1,
        highlightbackground=COLOR_MARRON_SUAVE,
        highlightcolor=COLOR_MARRON
    )
    campo_msg.pack(fill="x", ipady=8, pady=(5, 0))

    #  Checkbox simular alteracion - para forzar fallo de verificacion de firma
    frame_opciones = tk.Frame(ventana, bg=BG_VENTANA)
    frame_opciones.pack(fill="x", padx=28, pady=(10, 0))

    var_alteracion = tk.BooleanVar(value=False)
    chk_alteracion = tk.Checkbutton(
        frame_opciones,
        text="Simular alteracion de la contraseña  (corrompe la firma para forzar un fallo de verificacion)",
        variable=var_alteracion,
        font=("Segoe UI", 9),
        bg=BG_VENTANA, fg=COLOR_MARRON_MED,
        activebackground=BG_VENTANA,
        activeforeground=COLOR_MARRON,
        selectcolor=BG_VENTANA,
        cursor="hand2"
    )
    chk_alteracion.pack(anchor="w")

    #  Boton principal
    frame_btn = tk.Frame(ventana, bg=BG_VENTANA)
    frame_btn.pack(fill="x", padx=28, pady=(12, 0))

    btn = tk.Button(
        frame_btn,
        text="Procesar contraseña",
        font=FONT_BTN,
        bg=COLOR_MARRON, fg="white",
        activebackground=COLOR_MARRON_MED,
        activeforeground="white",
        relief="flat", bd=0,
        padx=20, pady=8,
        cursor="hand2"
    )
    btn.pack(anchor="w")

    def btn_hover_enter(e):
        btn.config(bg=COLOR_MARRON_MED)

    def btn_hover_leave(e):
        btn.config(bg=COLOR_MARRON)

    btn.bind("<Enter>", btn_hover_enter)
    btn.bind("<Leave>", btn_hover_leave)

    tk.Frame(ventana, height=1, bg=COLOR_SEPARADOR).pack(fill="x", padx=28, pady=(14, 0))

    #  Etiqueta de estado 
    frame_estado = tk.Frame(ventana, bg=BG_VENTANA)
    frame_estado.pack(fill="x", padx=28, pady=(8, 2))

    tk.Label(
        frame_estado,
        text="Estado:",
        font=FONT_ESTADO,
        bg=BG_VENTANA, fg=COLOR_TEXTO
    ).pack(side="left")

    lbl_estado = tk.Label(
        frame_estado,
        text="Esperando respuesta...",
        font=FONT_ESTADO,
        bg=BG_VENTANA, fg=COLOR_MARRON_SUAVE
    )
    lbl_estado.pack(side="left", padx=(6, 0))

    # Caja de resultados 
    salida = scrolledtext.ScrolledText(
        ventana,
        font=FONT_MONO,
        bg=BG_CAJA, fg=COLOR_TEXTO,
        relief="flat", bd=0,
        highlightthickness=1,
        highlightbackground=COLOR_SEPARADOR,
        state="disabled",
        wrap="word",
        padx=12, pady=10
    )
    salida.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    #  Logica del boton - se ejecuta al hacer click en "Procesar contraseña"
    def on_click():
        msg = campo_msg.get().strip()
        if not msg:
            messagebox.showwarning("Aviso", "Escribe una contraseña antes de procesar.")
            return

        btn.config(state="disabled", text="Procesando...")
        lbl_estado.config(text="Procesando...", fg=COLOR_MARRON_SUAVE)
        ventana.update()

        try:
            r = procesar(msg, simular_alteracion=var_alteracion.get())

            salida.config(state="normal")
            salida.delete("1.0", "end")

            # Configurar etiquetas de color
            salida.tag_config("normal",   foreground=COLOR_TEXTO,        font=FONT_MONO)
            salida.tag_config("mono",     foreground=COLOR_TEXTO,        font=FONT_MONO)
            salida.tag_config("gris",     foreground=COLOR_MARRON_SUAVE, font=FONT_MONO)
            salida.tag_config("cifrado",  foreground=COLOR_MARRON,       font=FONT_MONO)
            salida.tag_config("ok",       foreground=COLOR_VERDE,        font=("Consolas", 9, "bold"))
            salida.tag_config("error",    foreground=COLOR_ROJO,         font=("Consolas", 9, "bold"))
            salida.tag_config("titulo",   foreground=COLOR_MARRON,
                              font=("Segoe UI", 9, "bold"))
            salida.tag_config("sep",      foreground=COLOR_SEPARADOR,    font=FONT_MONO)

            def linea(texto="", tag="normal"):
                salida.insert("end", texto + "\n", tag)

            SEP_LARGO  = "─" * 60
            SEP_CORTO  = "─" * 40

            #  CIFRADO 
            linea(SEP_LARGO, "sep")
            linea("  PROCESO DE CIFRADO", "titulo")
            linea(SEP_LARGO, "sep")
            linea()
            linea(f"  SHA-256 (contraseña original)", "gris")
            linea(f"  {r['hash_original']}", "cifrado")
            linea()
            linea(f"  AES-256-GCM (texto cifrado)", "gris")
            linea(f"  {r['ct_aes']}", "cifrado")
            linea()
            linea(f"  ChaCha20-Poly1305 (texto cifrado)", "gris")
            linea(f"  {r['ct_cha']}", "cifrado")
            linea()

            #  DESCIFRADO 
            linea(SEP_LARGO, "sep")
            linea("  PROCESO DE DESCIFRADO", "titulo")
            linea(SEP_LARGO, "sep")
            linea()
            linea(f"  contraseña recuperada", "gris")
            linea(f"  {r['mensaje_rec']}", "normal")
            linea()

            firma_texto = "VALIDA" if r["firma_ok"] else "INVALIDA"
            firma_tag   = "ok"    if r["firma_ok"] else "error"
            linea(f"  Estado de firma:        {firma_texto}", firma_tag)

            integ_texto = "CORRECTA"     if r["hashes_ok"] else "COMPROMETIDA"
            integ_tag   = "ok"           if r["hashes_ok"] else "error"
            linea(f"  Integridad SHA-256:     {integ_texto}", integ_tag)
            linea()
            linea(f"  SHA-256 (contraseña descifrada)", "gris")
            linea(f"  {r['hash_rec']}", "gris")
            linea()

            # RENDIMIENTO 
            linea(SEP_LARGO, "sep")
            linea("  RENDIMIENTO", "titulo")
            linea(SEP_LARGO, "sep")
            linea()
            linea(f"  RSA - Generacion de claves :  {r['ms_keygen']:.2f} ms",  "normal")
            linea(f"  RSA - Proteccion de clave   :  {r['ms_rsa']:.2f} ms",    "normal")
            linea(f"  RSA - Firma digital         :  {r['ms_firma']:.2f} ms",  "normal")
            linea(f"  AES - Cifrado               :  {r['ms_aes_enc']:.4f} ms","normal")
            linea(f"  AES - Descifrado            :  {r['ms_aes_dec']:.4f} ms","normal")
            linea(f"  ChaCha20 - Cifrado          :  {r['ms_cha_enc']:.4f} ms","normal")
            linea(f"  ChaCha20 - Descifrado       :  {r['ms_cha_dec']:.4f} ms","normal")
            linea()

            sim  = r["ms_aes_enc"] + r["ms_aes_dec"] + r["ms_cha_enc"] + r["ms_cha_dec"]
            asim = r["ms_keygen"]  + r["ms_rsa"]     + r["ms_firma"]
            factor = asim / max(sim, 0.001)
            linea(f"  RSA es aprox. {factor:.0f}x mas lento que el cifrado simetrico", "gris")
            linea()
            linea(SEP_LARGO, "sep")

            salida.config(state="disabled")

            # Actualizar etiqueta de estado
            todo_ok = r["firma_ok"] and r["hashes_ok"]
            if todo_ok:
                lbl_estado.config(text="Verificacion correcta", fg=COLOR_VERDE)
            else:
                lbl_estado.config(text="Integridad comprometida", fg=COLOR_ROJO)

        except Exception as e:
            messagebox.showerror("Error durante el procesamiento", str(e))
            lbl_estado.config(text="Error en el procesamiento", fg=COLOR_ROJO)
        finally:
            btn.config(state="normal", text="Procesar contraseña")

    btn.config(command=on_click)

    ventana.mainloop()


if __name__ == "__main__":
    lanzar_gui()