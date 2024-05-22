from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import getpass

# Explicación del método
# 1. Generación de clave privada EC usando SECP256R1 como la curva elíptica.
# 2. El mensaje ingresado es firmado usando el algoritmo ECDSA con SHA-256 como la función hash.
# 3. La firma es verificada usando la clave pública correspondiente, asegurando que el mensaje no ha sido alterado.

# Generar una clave privada para el algoritmo de curva elíptica
private_key = ec.generate_private_key(ec.SECP256R1())

# Pedir al usuario que ingrese un mensaje para firmar
data = getpass.getpass("Por favor, ingresa un mensaje para firmar: ").encode()

# Firmar el mensaje
signature = private_key.sign(
    data,
    ec.ECDSA(hashes.SHA256())
)

print("Firma generada (en formato hexadecimal):", signature.hex())

# Obtener la clave pública asociada a la clave privada
public_key = private_key.public_key()

# Verificar la firma utilizando la clave pública
try:
    # Intentar verificar la firma
    public_key.verify(
        signature,
        data,
        ec.ECDSA(hashes.SHA256())
    )
    print("Verificación de la firma exitosa: El mensaje es auténtico.")
    print("Mensaje original:", data.decode())
except Exception as e:
    print("Verificación de la firma fallida: El mensaje o la firma han sido alterados.", e)

