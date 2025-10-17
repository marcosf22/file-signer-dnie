import base64, os, textwrap, threading, PyKCS11, sys, subprocess, socket, platform

from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk

# Esta es la ruta donde está guardada la librería, en MAC y linux puede cambiar.
pkcs11 = PyKCS11.PyKCS11Lib()
lib = pkcs11.load("C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll")

def lector(leido1):
    """
    La funcion lector permite acceder al lector de tarjetas.
    Comprueba cada 1 segundo si hay un lector disponible.
    La variable leido1 sirve para mostrar por pantalla una unica vez el mensaje.
    """
    
    cambiar_fondo("oak.png")
    lectores = readers()
    if lectores:
        root.after(0, limpiar_contenido)
        root.after(0, lambda: mostrar_mensaje("Introduce el DNIe en el lector de tarjetas.",2,25))
        root.after(0, lambda: tarjeta(lectores[0]))  # pasa al siguiente paso.
    elif not leido1:
        root.after(0, limpiar_contenido)
        root.after(0, lambda: mostrar_mensaje("Conecta el lector de tarjetas.", 2, 25))
        root.after(1000, lambda: lector(True))  # vuelve a intentarlo en 1 segundo.
        leido1 = True
    else:
        root.after(1000, lambda: lector(True))
    
def tarjeta(leido2):
    """
    La funcion tarjeta permite acceder a la tarjeta introducida por el lector.
    Comprueba cada 1 segundo si hay una tarjeta disponible.
    La variable leido2 sirve para mostrar por pantalla una unica vez el mensaje.
    """
    
    slots = pkcs11.getSlotList(tokenPresent=True)
    if slots:
        slot = slots[0]
        root.after(0, lambda: pantalla_pin(slot)) # pasa al siguiente paso.
    elif not leido2:
        root.after(0, limpiar_contenido)
        root.after(0, lambda: mostrar_mensaje("Introduce el DNIe en el lector de tarjetas.",2,25))
        root.after(1000, lambda: tarjeta(True)) # vuelve a intentarlo en 1 segundo.
        leido2 = True
    else:
        root.after(1000, lambda: tarjeta(True))

def iniciar_sesion(slot, pin):
    """
    La funcion iniciar_sesion nos permite entrar al DNIe con el pin introducido.
    """

    global sesion
    try:
        sesion = pkcs11.openSession(slot)
        sesion.login(pin)
        print("✅ Sesion iniciada correctamente.")
        root.after(0, pantalla_botones) # pasa al siguiente paso.
    except Exception as e:
        print("❌ Error al iniciar sesion:", e)
        root.after(0, mostrar_mensaje("ERROR. PIN INCORRECTO.", 2, 25))

def cerrar_sesion():
    """  
    La funcion cerrar_sesion nos permite salir del DNIe.
    """

    global sesion
    if sesion:
        try:
            sesion.logout()
            sesion.closeSession()
        except:
            pass
    root.destroy()

def exportar_certificado():
    """
    La funcion exportar_certificado nos permite exportar el certificado de firma
    almacenado en el DNIe introducido.

    Nos devuelve el certificado exportado en 2 formatos:
    - certificado.der
    - certificado.pem
    """

    global sesion
    # Buscamos los certificados disponibles en el DNIe.
    certificados = sesion.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
    if not certificados:
        raise Exception("No se encontro ningun certificado en el DNIe.")

    # Buscamos el certificado de FIRMA. 
    for certificado in certificados:
        cert_der = bytes(sesion.getAttributeValue(certificado, [PyKCS11.CKA_VALUE], True)[0])
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject = cert.subject.rfc4514_string().upper()

        if "FIRMA" in subject:
            cert = certificado
            break

    # Exportamos el cetificado en formato DER.
    with open("certificado.der", "wb") as f:
            f.write(cert_der)   

    # Exportamos el cetificado en formato PEM.
    b64 = base64.b64encode(cert_der).decode('ascii')
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END CERTIFICATE-----\n"
    with open("certificado.pem", "w") as f:
        f.write(pem)    

    # Función para mostrarlo por interfaz.
    mostrar_mensaje("Certificado exportado correctamente.", 1, 25)

def firmar_documento():
    """
    La funcion firmar_documento nos permite firmar un documento seleccionado (o documentos si se introduce una carpeta)
    con la clave privada de nuestro DNIe.
    """

    global sesion

    root.after(0, lambda: mostrar_mensaje("Elige que quieres firmar:", 1, 25))

    # Buscamos la clave privada de FIRMA en el DNIe.
    claves_privadas = sesion.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])    
    for clave in claves_privadas:
        label = sesion.getAttributeValue(clave, [PyKCS11.CKA_LABEL])[0]
        if label == "KprivFirmaDigital":
            clave_privada = clave
            break

    # Obtenemos los documentos a firmar.
    archivos = []

    def archivo():
        ruta = filedialog.askopenfilename(title="Selecciona archivo a firmar")
        archivos.append(ruta)
        root.after(0, firmar)

    # Si introducimos una carpeta, firma todos los documentos dentro de esa carpeta.
    def carpeta():
        ruta = filedialog.askdirectory(title="Selecciona carpeta a firmar")
        
        for dirpath, _, filenames in os.walk(ruta):
            for nombre in filenames:
                archivos.append(os.path.join(dirpath, nombre))

        root.after(0, firmar)
        
    # Botón de seleccionar ARCHIVO.
    boton_frame3 = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame3.place(relx=0.13, rely=0.5, relwidth=0.24, relheight=0.1)
    archiv = tk.Button(boton_frame3, text="ARCHIVO", bg="#7A0000", command=archivo, fg="#FFFFFF", font=("Fixedsys", int(22*root.winfo_width()/950)))
    archiv.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Botón de seleccionar CARPETA.
    boton_frame4 = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame4.place(relx=0.13, rely=0.61, relwidth=0.24, relheight=0.1)
    carpeta = tk.Button(boton_frame4, text="CARPETA", bg="#7A0000", command=carpeta, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    carpeta.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Firmamos todos los archivos.
    def firmar():
        try:
            if len(archivos) == 0:
                mostrar_mensaje("No hay archivos para firmar.", 1, 25)
            else:
                for archivo in archivos:
                    with open(archivo, "rb") as f:
                        data = f.read()

                    # Firmamos el documento.
                    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
                    firma_raw = bytes(sesion.sign(clave_privada, data, mechanism))
                    firma = archivo + ".sig"
                    with open(firma, "wb") as f:
                        f.write(firma_raw)

                if len(archivos) == 1:
                    mostrar_mensaje("Archivo firmado correctamente.", 1, 25)
                else:
                    mostrar_mensaje(f"{len(archivos)} archivos firmados correctamente.", 1, 25)
            root.after(2000, pantalla_botones)

        except Exception as e:
            mostrar_mensaje("Ha habido un error.", 1, 25)
            root.after(5000, pantalla_botones)    

def verificar_firma():
    """
    La funcion verificar_firma nos permite verificar la firma de un documento mediante la clave pública del DNIe.

    La clave pública la obtenemos del certificado exportado. En caso de que no exista el archivo, 
    lo exportaremos de nuevo, con el certificado presente en el DNIe introducido.
    """
    
    # Cargamos el certificado 
    try:
        with open("certificado.der", "rb") as f:
            der = f.read()
            certificado = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:

        # En caso de que no se detecte el certificado, lo exportamos de nuevo.
        exportar_certificado() 
        with open("certificado.der", "rb") as f:
            der = f.read()
            certificado = x509.load_der_x509_certificate(der, default_backend())

    # Obtenemos los documentos a verificar.
    archivo = filedialog.askopenfilename(title="Selecciona archivo original")
    sig_file = filedialog.askopenfilename(title="Selecciona archivo firmado")

    # Cargamos el documento y la firma
    try:
        with open(archivo, "rb") as f:
            data = f.read()
        with open(sig_file, "rb") as f:
            signature = f.read()
    except Exception as e:
        pass
    
    # Verificamos la firma
    try: 
        clave_publica = certificado.public_key()
        valido = clave_publica.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
            )
        
        # Función para mostrar mensaje por la interfaz.
        mostrar_mensaje("Firma del archivo válida.", 1, 25)

    except Exception as e:
        # Función para mostrar mensaje por la interfaz.
        mostrar_mensaje("Firma del archivo NO válida.", 1, 25)

# --- Funciones para la interfaz --- No tiene valor funcional, solo sirven para mostrar las cosas por la interfaz.

def limpiar_contenido():
    """"La función limpiar_contenido elimina las cosas que haya antes, como mensajes en cajas o botones."""
    for widget in content_frame.winfo_children():
        widget.destroy()

def mostrar_mensaje(mensaje, tipo, tamaño):
    """
    La función mostrar_mensaje nos ayuda a mostrar por la interfaz un mensaje con el estilo Pokemon.

    Hay 2 tipos de mensajes en función de la interfaz donde se muestre.
    - Tipo 1: Mensajes en la pantalla previa a iniciar sesión.
    - Tipo 2: Mensajes en la pantalla de inicio de sesión.
    """

    if tipo == 1:
        frame = tk.Frame(root, bg="#166E30", bd=8)
        frame.place(relx=0.02, rely=0.78, relwidth=0.43, relheight=0.2)

        label = tk.Label(frame, text="", bg="#166E30", fg="#F8F8F8", font=("Fixedsys", int(tamaño*root.winfo_width()/950)), justify="left", wraplength=int(330*root.winfo_width()/950))
    else:
        frame = tk.Frame(root, bg="#F8F8F8", bd=8)
        frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)

        label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", int(tamaño*root.winfo_width()/950)), justify="left", wraplength=int(660*root.winfo_width()/950))
    
    label.place(x=0, y=0)

    # Función para escribir el texto "letra por letra" como en el juego.
    def escribir_texto():
        texto = ""
        for letra in mensaje:
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start() # Si no ponemos esto peta xd.

# --- Pantallas ---
def pantalla_bienvenida():
    """Muestra el mensaje de bienvenida al programa."""
    limpiar_contenido()

    frame = tk.Frame(root, bg="#F8F8F8", bd=8)
    frame.place(relx=0.04, rely=0.78, relwidth=0.875, relheight=0.18)
    label = tk.Label(frame, text="", bg="#F8F8F8", fg="#575757", font=("Fixedsys", 25), justify="left", wraplength=660)
    label.place(x=0, y=0)

    def escribir_texto():
        texto = ""
        for letra in "Bienvenid@ al sistema de firma digital con DNIe.":
            texto += letra
            label.config(text=texto)

    threading.Thread(target=escribir_texto, daemon=True).start()

    root.after(3000, lambda: lector(False))

def pantalla_pin(slot):
    """Muestra la interfaz para introducir el PIN para acceder al DNIe."""
    limpiar_contenido()
    mostrar_mensaje("Presiona el botón 'PIN' para acceder a la terminal.",2,25)

    # Abrimos una terminal para acceder al PIN de forma segura.
    HOST = "localhost"
    def pedir_pin(callback):
        s = socket.socket(); s.bind((HOST, 0)); s.listen(1)
        port = s.getsockname()[1]
        code = f"import socket,getpass;pin=getpass.getpass('Introduzca el PIN: ');s=socket.socket();s.connect(('{HOST}',{port}));s.send(pin.encode());s.close()"
        if platform.system() == "Windows":
            subprocess.Popen([sys.executable, "-c", code], creationflags=0x00000010)
        elif platform.system() == "Darwin":
            subprocess.Popen(["osascript", "-e", f'tell app "Terminal" to do script "{sys.executable} -c \'{code}\'"'])
        else:  # Linux / Unix
            subprocess.Popen(["x-terminal-emulator", "-e", sys.executable, "-c", code])
        conn,_ = s.accept(); data = conn.recv(128); conn.close(); s.close()
        callback(data)

    boton_frame = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame.place(relx=0.03, rely=0.61, relwidth=0.33, relheight=0.11)
    boton = tk.Button(boton_frame, text="PIN", command=lambda: pedir_pin(confirmar_pin), bg="#7A0000", fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))  
    boton.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Esta forma no era tan segura y por eso está comentada.
    
    # pin_frame = tk.Frame(root, bg=None, bd=8)
    # pin_frame.place(relx=0.04, rely=0.62, relwidth=0.3, relheight=0.09)

    # pin_var = tk.StringVar()
    # pin_entry = ttk.Entry(pin_frame, textvariable=pin_var, show="*", font=("Arial", int(18*root.winfo_width()/950)), width=int(15*root.winfo_width()/950))
    # pin_entry.pack(pady=5)
    # pin_entry.focus()

    # Función que confirmar que haya un pin introducido.
    def confirmar_pin(pin):
        if not pin:
            root.after(0, mostrar_mensaje("Atención. Debes introducir tu PIN.", 2, 25))
            return
        iniciar_sesion(slot, pin)

    # # Botón de ACEPTAR.
    # boton_frame = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    # boton_frame.place(relx=0.65, rely=0.5, relwidth=0.3, relheight=0.09)
    # aceptar = tk.Button(boton_frame, text="Aceptar", bg="#7A0000", command=confirmar_pin, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    # aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # # Botón de CANCELAR.
    # boton_frame2 = tk.Frame(root, bg="#00187A", bd=8, relief="ridge")
    # boton_frame2.place(relx=0.65, rely=0.6, relwidth=0.3, relheight=0.09)
    # cancelar = tk.Button(boton_frame2, text="Cancelar", bg="#00187A", command=cerrar_sesion, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    # cancelar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

def cambiar_fondo(ruta_imagen):
    """Función que permite cambiar el fondo de la interfaz por otra imagen."""
    global current_bg_image, bg_label
    
    try:
        nueva_imagen = Image.open(ruta_imagen)
        current_bg_image = nueva_imagen
        
        width, height = root.winfo_width(), root.winfo_height()
        if width > 1 and height > 1:
            resized = current_bg_image.resize((width, height))
            bg_image_tk = ImageTk.PhotoImage(resized)
            
            # Si bg_label no existe lo creamos
            if not bg_label:
                bg_label = tk.Label(root)
                bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Actualizamos la imagen
            bg_label.config(image=bg_image_tk)
            bg_label.image = bg_image_tk
                
    except Exception as e:
        print(f"Error al cargar fondo {ruta_imagen}: {e}")

def on_resize(event):
    """Función que redimensiona fondo y texto."""
    if current_bg_image:
        width, height = root.winfo_width(), root.winfo_height()
        if width > 1 and height > 1:
            resized = current_bg_image.resize((width, height))
            bg_image = ImageTk.PhotoImage(resized)
            if bg_label:
                bg_label.config(image=bg_image)
                bg_label.image = bg_image

def pantalla_botones():
    """Pantalla principal que ejecuta las funciones del DNIe."""
    # Borrar todo EXCEPTO el fondo
    for widget in root.winfo_children():
        if widget != bg_label:
            widget.destroy()
    
    cambiar_fondo("batalla.png")
    
    # Botón de FRIMA.
    boton_frame = tk.Frame(root, bg="#7A0000", bd=8, relief="ridge")
    boton_frame.place(relx=0.5, rely=0.78, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame, text="Firmar", bg="#7A0000", command=firmar_documento, fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Botón de EXPORTAR CERTIFICADO.
    boton_frame2 = tk.Frame(root, bg="#00187A", bd=8, relief="ridge")
    boton_frame2.place(relx=0.5, rely=0.89, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame2, text="Exportar", bg="#00187A", command=exportar_certificado,fg="#FFFFFF", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Botón de VERIFICAR.
    boton_frame3 = tk.Frame(root, bg="#00B11E", bd=8, relief="ridge")
    boton_frame3.place(relx=0.75, rely=0.78, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame3, text="Verificar", bg="#00B11E", command=verificar_firma, fg="#FFFFFF", font=("Fixedsys", int(22*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    # Botón de SALIR y CERRAR SESIÓN.
    boton_frame4 = tk.Frame(root, bg="#EDED00", bd=8, relief="ridge")
    boton_frame4.place(relx=0.75, rely=0.89, relwidth=0.24, relheight=0.1)
    aceptar = tk.Button(boton_frame4, text="Salir", bg="#EDED00", command=cerrar_sesion, fg="#C2C2C2", font=("Fixedsys", int(25*root.winfo_width()/950)))
    aceptar.place(relx=0.5, rely=0.5, anchor="center", relwidth=1, relheight=1)

    mostrar_mensaje("Elige una opción:", 1, 25)

if __name__ == "__main__":
    """
    Función que inicializa el sistema de DNI.
    """
    root = tk.Tk()
    root.title("Sistema DNI")
    root.geometry("900x600")

    content_frame = ttk.Frame(root)
    content_frame.place(relx=0.5, rely=0.5, anchor="center")

    label = None
    current_bg_image = None
    bg_label = None
    
    root.bind("<Configure>", on_resize)
    root.after(0, pantalla_bienvenida)
    root.mainloop()