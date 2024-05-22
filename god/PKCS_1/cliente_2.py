import socket

def main():
    host = 'localhost'
    port = 6789

    # Establecer conexión con el servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((host, port))
        print("Conectado al servidor.")

        # Identificar al cliente como 'viewer'
        client.sendall(b"viewer")

        try:
            while True:
                # Recibir mensajes cifrados del servidor
                encrypted_message = client.recv(1024)
                if not encrypted_message:
                    print("Conexión cerrada por el servidor. Saliendo.")
                    break
                if encrypted_message.startswith(b"No hay"):
                    print("No hay mensajes disponibles. Esperando nuevos mensajes...")
                else:
                    print(f"Mensaje cifrado recibido: {encrypted_message}")
        except KeyboardInterrupt:
            print("Cliente cerrado manualmente.")

if __name__ == "__main__":
    main()
