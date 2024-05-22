from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs7
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# Cargar la clave privada y el certificado
with open("private_key.pem", "rb") as key_file:
    private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

with open("certificate.pem", "rb") as cert_file:
    certificate = load_pem_x509_certificate(cert_file.read(), backend=default_backend())

# Entrada del mensaje
message = input("Enter the message you want to sign: ").encode()

# Firmar los datos
signed_data = PKCS7SignatureBuilder().set_data(message).add_signer(
    certificate, private_key, hashes.SHA256()
).sign(serialization.Encoding.DER, [])

# Guardar los datos firmados en un archivo
with open("signed_data.der", "wb") as f:
    f.write(signed_data)

print("Signed data has been saved to signed_data.der")
