from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

def derive_key(password, salt):
    """Deriva una clave segura de la contraseña."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def main():
    # Generar clave privada RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Serializar la clave privada sin cifrar para mostrarla
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("Clave privada sin cifrar (PEM):\n", pem.decode())

    # Solicitar contraseña para cifrar la clave privada
    password = input("Introduce una contraseña para cifrar la clave privada: ")
    salt = os.urandom(16)  # Generar salt aleatorio

    # Cifrar la clave privada con la contraseña proporcionada
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    print("Clave privada cifrada (PEM):\n", encrypted_pem.decode())

    # Guardar la clave cifrada en un archivo para uso posterior
    with open('encrypted_private_key.pem', 'wb') as f:
        f.write(encrypted_pem)

    # Solicitar contraseña para descifrar la clave privada
    password_for_decryption = input("Introduce la contraseña para descifrar la clave privada: ")

    # Intentar descifrar la clave privada
    try:
        with open('encrypted_private_key.pem', 'rb') as f:
            encrypted_key = f.read()
        
        decrypted_key = serialization.load_pem_private_key(
            encrypted_key,
            password=password_for_decryption.encode(),
            backend=default_backend()
        )
        print("La clave privada ha sido descifrada con éxito.")
        
        # Mostrar la clave privada descifrada
        decrypted_pem = decrypted_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        print("Clave privada descifrada (PEM):\n", decrypted_pem.decode())
        
    except Exception as e:
        print("No se pudo descifrar la clave privada:", e)

if __name__ == "__main__":
    main()
