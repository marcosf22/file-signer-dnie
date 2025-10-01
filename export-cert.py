from smartcard.System import readers # Librería para acceder físicamente al lector.
from smartcard.Exceptions import *
import pkcs11 # Librería para hacer todo xd.
from pkcs11 import ObjectClass, Attribute
import getpass # Librería para ocultar el PIN.
import base64 # Librería para pasar a base64.

# Función que exporta certificado.
def exportCert():

    # Aquí literalmente ponemos la ruta donde está el archivo este.
    lib = pkcs11.lib("C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll")

    # Comprobamos que el lector está enchufado.
    lectores = readers()
    if not lectores:
        raise SystemExit("No hay lectores detectados")
    lector = lectores[0]
    print("Lectura correcta por: ", lector)

    try:

        # Creamos la conexión con el DNI.
        conn = lector.createConnection()
        conn.connect()

        token = lib.get_token()
        print("Token:", token)

        # Accedemos al DNI cons la contraseña del DNI (CUIDADO, SÓLO 3 INTENTOS).
        contraseña = getpass.getpass("Introduce PIN: ")
        with token.open(user_pin=contraseña) as sesion:
            print('Inicio correcto')   

            # Extraemos los certificados que haya en el DNI.
            certificados = list(sesion.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))   
            print(len(certificados), " certificados encontrados")
            
            # Guardamos los certificados en un archivo .DER.
            certificado = certificados[0]
            der = certificado[pkcs11.Attribute.VALUE]
            with open('certificado.der', 'wb') as g:
                g.write(der)

            # Lo pasamos a formato .PEM.
            pem = base64.b64encode(der).decode()
            with open('certificado.pem', 'w') as h:
                h.write(f"-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----\n")

    except pkcs11.exceptions.PKCS11Error as e:
        print(e)
    except 	SmartcardException as f:
        print(f)
