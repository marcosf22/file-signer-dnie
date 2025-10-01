from smartcard.System import readers # Librería para acceder físicamente al lector.
import pkcs11 # Librería para hacer todo xd.
import getpass # Librería para ocultar el PIN.

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
    with token.open(user_pin=contraseña) as session:
        print('Inicio correcto')      

# Excepción que salta cuando fallamos el PIN.
except pkcs11.exceptions.PinIncorrect:
    print("PIN incorrecto")