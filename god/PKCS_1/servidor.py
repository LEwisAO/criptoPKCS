import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Lista para mantener las conexiones de los viewers
viewers = []
# Lista para almacenar los mensajes cifrados
encrypted_messages = []

def handle_client(client_socket, addr, public_key_pem, private_key):
    global viewers, encrypted_messages
    print(f"Conectado a {addr}")

    try:
        # Recibir identificación del cliente
        client_type = client_socket.recv(1024).decode().strip()

        if client_type == 'sender':
            client_socket.sendall(public_key_pem)  # Enviar clave pública al cliente

            # Recibir y almacenar mensaje cifrado del cliente
            encrypted_message = client_socket.recv(1024)
            print("Mensaje cifrado recibido.")
            encrypted_messages.append(encrypted_message)  # Almacenar el mensaje cifrado

            # Opcional: Descifrar y mostrar el mensaje
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Mensaje descifrado: {decrypted_message.decode()}")

            # Notificar a los viewers
            for viewer in viewers:
                viewer.sendall(encrypted_message)
            
            client_socket.close()

        elif client_type == 'viewer':
            viewers.append(client_socket)  # Agregar este viewer a la lista
            while True:  # Mantener la conexión abierta
                for message in encrypted_messages:
                    client_socket.sendall(message)
                encrypted_messages = []  # Resetear la lista tras enviar

    except Exception as e:
        print(f"Error: {e}")
        if client_socket in viewers:
            viewers.remove(client_socket)
        client_socket.close()

def main():
    # Generar el par de claves RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serializar la clave pública para compartirla con el cliente
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Configurar el socket del servidor
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 6789))
    server.listen(5)
    print("Servidor escuchando en puerto 6789")

    try:
        while True:
            client_socket, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, addr, public_key_pem, private_key))
            thread.start()
    except KeyboardInterrupt:
        print("Servidor cerrando.")
        server.close()

if __name__ == "__main__":
    main()
