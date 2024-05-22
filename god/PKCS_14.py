from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import getpass


# Explicación del método
# 1. Derivación de una clave segura usando HKDF.
# 2. Uso de la clave para cifrar un mensaje.
# 3. Requerimiento de reingreso de la información compartida para verificar el acceso antes del descifrado.
# 4. AES en modo CFB es utilizado para cifrado y descifrado, con un IV constante a través de ambos procesos.

def create_hkdf(ikm, salt, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )

# Generar una semilla aleatoria
salt = urandom(16)
info = b'handshake data'

# Permitir al usuario ingresar información compartida para la derivación de clave
ikm = getpass.getpass("Por favor, ingresa información compartida para la derivación de clave: ").encode()

hkdf = create_hkdf(ikm, salt, info)
key = hkdf.derive(ikm)
print("Clave derivada (en hexadecimal):", key.hex())

# Generar un IV y usar el mismo para cifrar y descifrar
iv = urandom(16)

# Cifrar un mensaje usando la clave derivada
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
message = getpass.getpass("Ingresa un mensaje para cifrar: ").encode()
ciphertext = encryptor.update(message) + encryptor.finalize()
print("Mensaje cifrado (en hexadecimal):", ciphertext.hex())

# Pedir al usuario que reingrese la información compartida para descifrado
ikm_reentered = getpass.getpass("Reingresa la información compartida para descifrar el mensaje: ").encode()
hkdf_reentered = create_hkdf(ikm_reentered, salt, info)
key_reentered = hkdf_reentered.derive(ikm_reentered)

if key_reentered == key:
    # Descifrar el mensaje usando el mismo IV
    decryptor = Cipher(algorithms.AES(key_reentered), modes.CFB(iv), backend=default_backend()).decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    print("Mensaje descifrado:", decrypted_message.decode())
else:
    print("Error: La información compartida no coincide. Acceso denegado al mensaje descifrado.")


