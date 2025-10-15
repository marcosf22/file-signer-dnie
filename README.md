# file-signer-dnie
Herramienta de firma digital con DNIe. Firma archivos usando la clave privada del DNIe y verifica firmas con la clave pública del certificado.

Para su uso proponemos 2 versiones:
- *Comandos:* El archivo dni.py contiene el código necesario para ejecutar las funciones mediante linea de comandos.
- *Interfaz gráfica:* Para hacerlo más visual y entretenido hemos desarrollado una interfaz gráfica basada en un juego de Pokemon.

Ambos programas cumplen con las mismas características:
- Firmar archivos (archivo individual o todos los archivos de una carpeta dada).
- Verificar la firma de un archivo.
- Exportar el certificado de FIRMA de un DNI.

Para ejecutar los programas es necesario tener descargado openSC, normalmente en la siguiente ruta:
"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

Podemos obtener la descarga en el siguiente enlace:
https://github.com/OpenSC/OpenSC/releases/tag/0.26.1

A su vez, es necesario instalar librerías de python que no vienen instaladas de forma predeterminada:
tkinter, getpass, smartcard, cryptography, PyKCS11.

En el caso de querer ejecutar el programa con la interfaz gráfica, es necesario tener descargados y en el mismo directorio que el progama principal las imágenes de fondo (batalla.png, oak.png).

Por último, es necesario un lector de tarjetas inteligente USB y DNIe.

*Limitaciones:*
Durante el desarrollo del programa hemos detectado una limitación a la hora de verificar los documentos firmados.
Cuando renuevas los certificados del DNI, los antiguos no desaparecen y permanecen en memoria. Por ello, existe la posibilidad que al firmar un archivo, se use la clave privada NUEVA, pero a la hora de verificarlo se use la clave pública ANTIGUA, de forma que no se verifica correctamente.
