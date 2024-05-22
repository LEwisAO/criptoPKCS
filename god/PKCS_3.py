from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class User:
    """Clase que representa a un usuario en un intercambio de claves DH y encriptación de mensajes."""
    def __init__(self, name, parameters):
        self.name = name
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    def generate_shared_secret(self, other_public_key):
        """Genera un secreto compartido usando la clave pública de otro usuario."""
        shared_secret = self.private_key.exchange(other_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)

    def encrypt_message(self, key, message):
        """Encripta un mensaje usando AES."""
        iv = os.urandom(16)  # IV para AES
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CFB(iv)
        ).encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + encrypted_message  # Retornar IV + mensaje cifrado para la desencriptación

    def decrypt_message(self, key, encrypted_message):
        """Desencripta un mensaje usando AES."""
        iv = encrypted_message[:16]  # Extraer el IV que es los primeros 16 bytes
        actual_message = encrypted_message[16:]  # El resto es el mensaje
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CFB(iv)
        ).decryptor()
        return decryptor.update(actual_message) + decryptor.finalize()

def main():
    # Generar parámetros DH (se pueden generar una vez y reutilizar)
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Crear usuarios
    alice = User("Alice", parameters)
    bob = User("Bob", parameters)

    # Alice y Bob generan sus claves compartidas una vez
    alice_shared_key = alice.generate_shared_secret(bob.public_key)
    bob_shared_key = bob.generate_shared_secret(alice.public_key)

    # Asegurar que las claves compartidas coincidan
    assert alice_shared_key == bob_shared_key, "Las claves compartidas deben coincidir"

    messages = ["Hola Bob, este es el primer mensaje seguro de Alice.",
                "Hola de nuevo Bob, aquí otro mensaje seguro de Alice."]

    for message in messages:
        # Alice envía mensajes a Bob
        encrypted_message = alice.encrypt_message(alice_shared_key, message)
        print(f"Alice envió: {encrypted_message}")

        # Bob recibe y desencripta el mensaje
        decrypted_message = bob.decrypt_message(bob_shared_key, encrypted_message)
        print(f"Bob recibió y desencriptó: {decrypted_message.decode()}")

        # Confirmar que se está utilizando la misma clave
        print("Clave compartida utilizada: {}".format(alice_shared_key.hex()))

if __name__ == "__main__":
    main()
