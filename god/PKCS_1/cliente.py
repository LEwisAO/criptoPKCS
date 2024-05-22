import socket

def main():
    host = 'localhost'
    port = 6789

    # Establecer conexión con el servidor
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print("Conectado al servidor.")

    # Identificar al cliente como 'sender'
    client.sendall(b"sender")

    # Recibir la clave pública del servidor
    public_key_pem = client.recv(2048)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Permitir al usuario escribir un mensaje
    message = input("Escribe el mensaje que quieres enviar: ")

    # Cifrar el mensaje
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Enviar mensaje cifrado al servidor
    client.sendall(encrypted_message)
    print("Mensaje cifrado enviado al servidor.")

    client.close()

if __name__ == "__main__":
    main()
