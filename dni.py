import base64, getpass, os, textwrap, sys, time, PyKCS11

from tkinter import filedialog
from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

pkcs11 = PyKCS11.PyKCS11Lib()
lib = pkcs11.load("C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll")

def iniciar_sesion():
    """
    La funcion iniciar_sesion nos permite entrar al DNIe con el pin introducido.
    """

    # Esperamos un lector disponible.
    lectores = False
    leido = False
    while not lectores:
        lectores = readers()
        lector = lectores[0] if lectores else None
        if not lectores and not leido:
            print("\nEsperando lector...")
            leido = True
        elif lectores:
            print("Lectura correcta por: ", lector)

    # Esperamos a que se introduzca un DNI por el lector.
    slots = False
    leido = False
    while not slots:
        slots = pkcs11.getSlotList(tokenPresent=True)
        slot = slots[0] if slots else None
        if not slots and not leido:
            print("\nEsperando tarjeta...")
            leido = True
        elif slots:
            print("Tarjeta detectada en la ranura: ", slot)

    # Introducimos el PIN e iniciamos sesión.
    password = None
    while not password:
        password = getpass.getpass("\nIntroduce el PIN del DNIe: ")

    sesion = pkcs11.openSession(slot)
    sesion.login(password)
    print('\nInicio correcto')
    return sesion

def cerrar_sesion(sesion):
    """Función para cerrar el programa"""
    if sesion:
        try:
            sesion.logout()
            sesion.closeSession()
        except:
            pass
    print('\nCierre correcto')
    time.sleep(1)
    sys.exit()

def exportar_certificado(sesion):
    """
    La funcion exportar_certificado nos permite exportar el certificado de firma
    almacenado en el DNIe introducido.

    Nos devuelve el certificado exportado en 2 formatos:
    - certificado.der
    - certificado.pem
    """

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

    print("\nCerificado exportado correctamente")

    # Exportamos el cetificado en formato DER
    with open("certificado.der", "wb") as f:
            f.write(cert_der)   

    # Exportamos el cetificado en formato PEM
    b64 = base64.b64encode(cert_der).decode('ascii')
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END CERTIFICATE-----\n"
    with open("certificado.pem", "w") as f:
        f.write(pem)  

    time.sleep(3)  

def firmar_documento(sesion):
    """
    La funcion firmar_documento nos permite firmar un documento seleccionado (o documentos si se introduce una carpeta)
    con la clave privada de nuestro DNIe.
    """

    print("\n¿Que quieres firmar?\n")
    print("1. Archivo")
    print("2. Carpeta\n")
    eleccion = input("")

    # Buscamos la clave privada de FIRMA en el DNIe.
    claves_privadas = sesion.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])    
    for clave in claves_privadas:
        label = sesion.getAttributeValue(clave, [PyKCS11.CKA_LABEL])[0]
        if label == "KprivFirmaDigital":
            clave_privada = clave
            break

    # Obtenemos los documentos a firmar.
    archivos = []

    # Si introducimos un archivo, lo firmamos.
    if eleccion == "1":
        ruta = filedialog.askopenfilename(title="Selecciona archivo a firmar")
        archivos.append(ruta)

    # Si introducimos una carpeta, firma todos los documentos dentro de esa carpeta.
    elif eleccion == "2":
        ruta = filedialog.askdirectory(title="Selecciona carpeta a firmar")
        for dirpath, _, filenames in os.walk(ruta):
            for nombre in filenames:
                archivos.append(os.path.join(dirpath, nombre))
        
    # Firmamos todos los archivos.
    try:
        if len(archivos) == 0:
            print("\nNo hay archivos para firmar.")
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
                print("\nArchivo firmado correctamente.")
            else:
                print(f"\n{len(archivos)} archivos firmado correctamente.")

        time.sleep(3)

    except Exception as e:
        print(e)

def verificar_firma(sesion):
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
        exportar_certificado(sesion) 
        with open("certificado.der", "rb") as f:
            der = f.read()
            certificado = x509.load_der_x509_certificate(der, default_backend())

    # Obtenemos los documentos a verificar.
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
        
        print("\n✅ Firma válida")

    except Exception as e:
        print("\n❌ Firma NO válida")

    time.sleep(3)

if __name__ == "__main__":
    try:
        print("\nBienvenido al sistema de firma\n")
        sesion = iniciar_sesion()
        while True:
            print("\nElige opcion:\n")
            print("1. Firmar documento")
            print("2. Verificar firma")
            print("3. Exportar certificado")
            print("4. Salir\n")
            eleccion = input("")
            if eleccion == "1":
                firmar_documento(sesion)
            elif eleccion == "2":
                verificar_firma(sesion)
            elif eleccion == "3":
                exportar_certificado(sesion)
            elif eleccion == "4": 
                cerrar_sesion(sesion)

    except Exception as e:
        print("Error:", e)
