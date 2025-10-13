import base64
import getpass
import textwrap
import threading
import time
from tkinter import filedialog, messagebox
from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import PyKCS11
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont
from PIL import Image, ImageTk

pkcs11 = PyKCS11.PyKCS11Lib()
lib = pkcs11.load("C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll")
current_bg_image = None
bg_label = None

def lector(leido1):
    cambiar_fondo("oak.png")
    lectores = readers()
    if lectores:
        root.after(0, pantalla_dni)
        root.after(0, lambda: tarjeta(lectores[0]))  # pasa al siguiente paso
    elif not leido1:
        root.after(0, pantalla_lector)
        root.after(950, lambda: lector(True))  # vuelve a intentarlo en 1 segundo
        leido1 = True
    else:
        root.after(950, lambda: lector(True))

def tarjeta(leido2):

    slots = pkcs11.getSlotList(tokenPresent=True)
    if slots:
        slot = slots[0]
        root.after(0, lambda: pantalla_pin(slot))
    elif not leido2:
        root.after(0, pantalla_dni)
        root.after(950, lambda: tarjeta(True))
        leido2 = True
    else:
        root.after(950, lambda: tarjeta(True))

def iniciar_sesion_con_pin(slot, pin):
    global sesion
    try:
        sesion = pkcs11.openSession(slot)
        sesion.login(pin)
        print("✅ Sesión iniciada correctamente.")
        root.after(0, pantalla_botones(sesion))
    except Exception as e:
        print("❌ Error al iniciar sesión:", e)
        messagebox.showerror("Error", "PIN incorrecto o error de acceso al DNIe.")

def cerrar_sesion():
    global sesion
    if sesion:
        try:
            sesion.logout()
            sesion.closeSession()
        except:
            pass
    root.destroy()

def exportar_certificado():
    global sesion
    # Buscamos los certificados disponibles en el DNIe
    certificados = sesion.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certificados:
        raise Exception("No se encontró ningún certificado en el DNIe.")

    # Buscamos el certificado de firma 
    for certificado in certificados:
        cert_der = bytes(sesion.getAttributeValue(certificado, [PyKCS11.CKA_VALUE], True)[0])
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject = cert.subject.rfc4514_string().upper()

        if "FIRMA" in subject:
            cert = certificado
            break

    # Exportamos el cetificado en formato DER
    with open("certificado.der", "wb") as f:
            f.write(cert_der)   

    # Exportamos el cetificado en formato PEM
    b64 = base64.b64encode(cert_der).decode('ascii')
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END CERTIFICATE-----\n"
    with open("certificado.pem", "w") as f:
        f.write(pem)    

    frame = tk.Frame(root, bg="#166E30", bd=8)
    frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

    label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(18*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
    label.place(x=0, y=0)

    mensaje = "Certificados exportados correctamente."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

def firmar_documento():
    global sesion
    # Obtenemos el documento a firmar
    archivo = filedialog.askopenfilename(title="Selecciona archivo a firmar")
    with open(archivo, "rb") as f:
        data = f.read()

    # Buscamos la clave privada de firma en el DNIe
    claves_privadas = sesion.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])    
    for clave in claves_privadas:
        label = sesion.getAttributeValue(clave, [PyKCS11.CKA_LABEL])[0]
        if label == "KprivFirmaDigital":
            clave_privada = clave
            break

    # Firmamos el documento
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
    firma_raw = bytes(sesion.sign(clave_privada, data, mechanism))
    firma = archivo + ".sig"
    with open(firma, "wb") as f:
        f.write(firma_raw)
    
    frame = tk.Frame(root, bg="#166E30", bd=8)
    frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

    label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(18*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
    label.place(x=0, y=0)

    mensaje = "Archivo firmado correctamente."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

def verificar_firma():
    
    # Cargamos el certificado 
    try:
        with open("certificado.der", "rb") as f:
            der = f.read()
            certificado = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:
        exportar_certificado() 
        with open("certificado.der", "rb") as f:
            der = f.read()
            certificado = x509.load_der_x509_certificate(der, default_backend())

    archivo = filedialog.askopenfilename(title="Selecciona archivo original")
    sig_file = filedialog.askopenfilename(title="Selecciona archivo firmado")
    # Cargamos el documento y la firma
    with open(archivo, "rb") as f:
        data = f.read()
    with open(sig_file, "rb") as f:
        signature = f.read()

    # Verificamos la firma
    try: 
        clave_publica = certificado.public_key()
        valido = clave_publica.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
            )
        frame = tk.Frame(root, bg="#166E30", bd=8)
        frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

        label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(18*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
        label.place(x=0, y=0)

        mensaje = "Firma del archivo válida."

        def escribir_texto():
            texto = ""
            for letra in mensaje:
                texto += letra
                label.config(text=texto)

        threading.Thread(target=escribir_texto, daemon=True).start()
    except Exception as e:
        frame = tk.Frame(root, bg="#166E30", bd=8)
        frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

        label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(18*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
        label.place(x=0, y=0)

        mensaje = "Firma del archivo NO válida."

        def escribir_texto():
            texto = ""
            for letra in mensaje:
                texto += letra
                label.config(text=texto)

        threading.Thread(target=escribir_texto, daemon=True).start()
        valido = False
    return valido

# --- Funciones de utilidad ---
def limpiar_contenido():
    for widget in content_frame.winfo_children():
        widget.destroy()

def on_resize(event):
    """Redimensiona fondo y texto."""
    width, height = root.winfo_width(), root.winfo_height()
    resized = original_bg.resize((width, height))
    bg_image = ImageTk.PhotoImage(resized)
    bg_label.config(image=bg_image)
    bg_label.image = bg_image
    if label:
        new_size = max(12, int(height / 20))
        label.config(font=("Arial", new_size))

# --- Pantallas ---
def pantalla_bienvenida():
    limpiar_contenido()

    # --- Cuadro tipo Pokémon ---
    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)

    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", 25), justify="left", wraplength=660)
    label.place(x=0, y=0)

    mensaje = "Bienvenido al sistema de autofirma con DNIe."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

    root.after(3000, lambda: lector(False))

def pantalla_lector():
    limpiar_contenido()

    # --- Cuadro tipo Pokémon ---
    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)
    
    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", int(25*root.winfo_width()/950)), justify="left", wraplength=int(660*root.winfo_width()/950))
    label.place(x=0, y=0)

    mensaje = "Conecta el lector de tarjetas."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

def pantalla_dni():
    limpiar_contenido()

    # --- Cuadro tipo Pokémon ---
    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)

    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", int(25*root.winfo_width()/950)), justify="left", wraplength=int(660*root.winfo_width()/950), anchor="center")
    label.place(x=0, y=0)

    mensaje = "Introduce el DNIe en el lector de tarjetas."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

def pantalla_pin(slot):
    limpiar_contenido()

    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)

    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", int(25*root.winfo_width()/950)), justify="left", wraplength=int(660*root.winfo_width()/950), anchor="center")
    label.place(x=0, y=0)

    mensaje = "Introduce el pin del DNIe."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

    pin_frame = tk.Frame(root, bg=None, bd=8)
    pin_frame.place(relx=0.04, rely=0.62, relwidth=0.3, relheight=0.09)

    pin_var = tk.StringVar()
    pin_entry = ttk.Entry(pin_frame, textvariable=pin_var, show="*", font=("Arial", int(18*root.winfo_width()/950)), width=int(15*root.winfo_width()/950))
    pin_entry.pack(pady=5)
    pin_entry.focus()

    def confirmar_pin():
        pin = pin_var.get().strip()
        if not pin:
            messagebox.showwarning("Atención", "Debes introducir tu PIN.")
            return
        iniciar_sesion_con_pin(slot, pin)

    boton_frame = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame.place(relx=0.65, rely=0.5, relwidth=0.3, relheight=0.09)
    aceptar = tk.Button(boton_frame, text="Aceptar", bg="#7A0000", command=confirmar_pin, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    boton_frame2 = tk.Frame(root, bg="#00187A", bd=8, relief="ridge")
    boton_frame2.place(relx=0.65, rely=0.6, relwidth=0.3, relheight=0.09)
    aceptar = tk.Button(boton_frame2, text="Cancelar", bg="#00187A", command=pantalla_dni, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)
    
def cambiar_fondo(ruta_imagen):
    global current_bg_image, bg_label
    
    try:
        nueva_imagen = Image.open(ruta_imagen)
        current_bg_image = nueva_imagen
        
        width, height = root.winfo_width(), root.winfo_height()
        if width > 1 and height > 1:
            resized = current_bg_image.resize((width, height))
            bg_image_tk = ImageTk.PhotoImage(resized)
            
            # Si bg_label no existe, créalo
            if not bg_label:
                bg_label = tk.Label(root)
                bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Actualizar la imagen
            bg_label.config(image=bg_image_tk)
            bg_label.image = bg_image_tk
                
    except Exception as e:
        print(f"Error al cargar fondo {ruta_imagen}: {e}")

def on_resize(event):
    """Redimensiona fondo y texto."""
    if current_bg_image:
        width, height = root.winfo_width(), root.winfo_height()
        if width > 1 and height > 1:
            resized = current_bg_image.resize((width, height))
            bg_image = ImageTk.PhotoImage(resized)
            if bg_label:
                bg_label.config(image=bg_image)
                bg_label.image = bg_image

def pantalla_botones(sesion):

    # Borrar todo lo que hay en pantalla (excepto el fondo)
    for widget in root.winfo_children():
        if widget != bg_label:  # No destruir el label del fondo
            widget.destroy()
    
    # Cambiar el fondo
    cambiar_fondo("batalla.png")  # Tu nueva imagen
    
    # Aquí añades tus botones u otros elementos
    boton_frame = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame.place(relx=0.5, rely=0.78, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame, text="Firmar", bg="#7A0000", command=firmar_documento, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    boton_frame2 = tk.Frame(root, bg="#00187A", bd=8, relief="ridge")
    boton_frame2.place(relx=0.5, rely=0.89, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame2, text="Exportar", bg="#00187A", command=exportar_certificado, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    boton_frame3 = tk.Frame(root, bg="#00B11E", bd=8, relief="ridge")
    boton_frame3.place(relx=0.75, rely=0.78, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame3, text="Verificar", bg="#00B11E", command=verificar_firma, fg="#FFFFFF", font=("Fixedsys", int(22*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    boton_frame4 = tk.Frame(root, bg="#EDED00", bd=8, relief="ridge")
    boton_frame4.place(relx=0.75, rely=0.89, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame4, text="Salir", bg="#EDED00", command=cerrar_sesion, fg="#C2C2C2", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    frame = tk.Frame(root, bg="#166E30", bd=8)
    frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

    label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(18*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
    label.place(x=0, y=0)

    mensaje = "Elige una opción:"

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

def pantalla_final():
    limpiar_contenido()

    # --- Cuadro tipo Pokémon ---
    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)

    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", int(25*root.winfo_width()/950)), justify="left", wraplength=int(660*root.winfo_width()/950), anchor="center")
    label.place(x=0, y=0)

    mensaje = "Proceso finalizado."

    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()
    
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Sistema DNI")
    root.geometry("900x600")

    content_frame = ttk.Frame(root)
    content_frame.place(relx=0.5, rely=0.5, anchor="center")

    label = None
    
    root.bind("<Configure>", on_resize)
    pantalla_bienvenida()
    root.mainloop()