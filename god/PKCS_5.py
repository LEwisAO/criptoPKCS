from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def derive_key(password: str, salt: bytes):
    """Deriva una clave usando PBKDF2."""
    password_bytes = password.encode('utf-8')  # Codificar la contraseña en bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def encrypt_message(key, message: str):
    """Cifra un mensaje usando AES."""
    message_bytes = message.encode('utf-8')  # Convertir el mensaje a bytes
    iv = os.urandom(16)  # Generar un IV aleatorio
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
    return iv + encrypted_message  # Concatenar IV al mensaje cifrado para uso en descifrado

def decrypt_message(key, encrypted_message: bytes):
    """Descifra un mensaje usando AES."""
    iv = encrypted_message[:16]  # Extraer el IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.decode('utf-8')  # Decodificar el mensaje descifrado a cadena

def main():
    # Entrada de usuario para la contraseña y el mensaje
    password = input("Introduce tu contraseña para cifrar: ")
    message = input("Introduce el mensaje que quieres cifrar: ")
    
    salt = os.urandom(16)  # Generar una sal aleatoria

    # Derivar clave para cifrado
    key = derive_key(password, salt)

    # Cifrar mensaje
    encrypted_message = encrypt_message(key, message)
    print("Mensaje cifrado:", encrypted_message)

    # Pedir la contraseña nuevamente para descifrar
    password_for_decryption = input("Introduce tu contraseña para descifrar: ")
    key_for_decryption = derive_key(password_for_decryption, salt)

    # Descifrar mensaje
    decrypted_message = decrypt_message(key_for_decryption, encrypted_message)
    print("Mensaje descifrado:", decrypted_message)

if __name__ == "__main__":
    main()
