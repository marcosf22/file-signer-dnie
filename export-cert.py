import base64
import getpass
import textwrap
from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import PyKCS11

pkcs11 = PyKCS11.PyKCS11Lib()
lib = pkcs11.load("C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll")

def iniciar_sesion():
    lectores = False
    while not lectores:
        # Aqui podemos lanzar un aviso en pantalla de que no hay lectores conectados.
        lectores = readers()
        lector = lectores[0] if lectores else None

    print("Lectura correcta por: ", lector)

    slots = False
    while not slots:
        # Aqui podemos lanzar un aviso en pantalla de que no hay dni conectado.
        slots = pkcs11.getSlotList(tokenPresent=True)
        slot = slots[0] if slots else None

    print("Tarjeta detectada en la ranura: ", slot)

    password = getpass.getpass("Introduce el PIN del DNIe: ")
    sesion = pkcs11.openSession(slot)
    sesion.login(password)

    print('Inicio correcto')

    return sesion

def cerrar_sesion(sesion):
    if sesion:
        try:
            sesion.logout()
            sesion.closeSession()
        except:
            pass
    print('Cierre correcto')

def exportar_certificado(sesion):
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

    print("Cerificados exportados correctamente")

    # Exportamos el cetificado en formato DER
    with open("certificado.der", "wb") as f:
            f.write(cert_der)   

    # Exportamos el cetificado en formato PEM
    b64 = base64.b64encode(cert_der).decode('ascii')
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END CERTIFICATE-----\n"
    with open("certificado.pem", "w") as f:
        f.write(pem)    

def firmar_documento(sesion):

    # Obtenemos el documento a firmar
    archivo = "sanchezcorrupto.pdf"
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

    return archivo, firma

def verificar_firma(archivo, sig_file):
    # Cargamos el certificado 
    with open("certificado.der", "rb") as f:
        der = f.read()
        certificado = x509.load_der_x509_certificate(der, default_backend())
    
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
        print("✅ Firma válida")
    except Exception as e:
        print("❌ Firma NO válida")
        valido = False
    return valido

if __name__ == "__main__":

    try:
        sesion = iniciar_sesion()
        cert = exportar_certificado(sesion)
        archivo, sig_file = firmar_documento(sesion)
        valido = verificar_firma(archivo, sig_file)
    except Exception as e:
        print("Error:", e)
    finally:
        cerrar_sesion(sesion)
