import asn1crypto.cms
import asn1crypto.pem
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

# Cargar los datos firmados desde un archivo
with open("signed_data.der", "rb") as f:
    signed_data = f.read()

# Cargar el certificado del firmante
with open("certificate.pem", "rb") as cert_file:
    certificate = load_pem_x509_certificate(cert_file.read(), backend=default_backend())

# Parsear los datos firmados
if asn1crypto.pem.detect(signed_data):
    _, _, signed_data = asn1crypto.pem.unarmor(signed_data)

content_info = asn1crypto.cms.ContentInfo.load(signed_data)
signed_data_obj = content_info['content']

# Verificar la firma
for signer_info in signed_data_obj['signer_infos']:
    signature = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs'].dump()
    
    # Crear la data que se firmó
    signed_data = b'\x31' + signed_attrs[1:]
    
    # Obtener la clave pública del certificado
    public_key = certificate.public_key()
    
    # Verificar la firma
    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
        print("The signature is valid.")
        # Mostrar el mensaje original
        original_message = content_info['content']['encap_content_info']['content'].native
        print("Original Message:", original_message)
    except Exception as e:
        print("The signature is invalid:", e)
