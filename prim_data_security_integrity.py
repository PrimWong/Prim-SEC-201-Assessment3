from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    """ Generate RSA public and private keys. """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Extract and print the RSA key components
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Print keys in PEM format
    print("Private Key:")
    print(pem.decode())
    print("Public Key:")
    print(public_pem.decode())
    
    return private_key, public_key

def encrypt_message(message, public_key):
    """ Encrypt a message using the given public key. """
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\nCiphertext outputs | Encrypted message (bytes):", encrypted)
    return encrypted

def decrypt_message(encrypted_message, private_key):
    """ Decrypt a message using the given private key. """
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

def sign_message(message, private_key):
    """ Sign a message using the given private key. """
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\nDigital signature of the plaintext (bytes):", signature)
    return signature

def verify_signature(message, signature, public_key):
    """ Verify a digital signature using the given public key. """
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def print_private_key_details(private_key):
    """ Print private key's prime numbers p and q, if accessible. """
    try:
        # Attempt to access private key components directly
        private_numbers = private_key.private_numbers()
        p = private_numbers.p
        q = private_numbers.q
        print("\nPrime p:", p)
        print("\nPrime q:", q)
    except AttributeError:
        print("\nDirect access to p and q is not supported by this cryptography backend.")

def main():
    print("Generating RSA keys...")
    private_key, public_key = generate_keys()
    
    print("\nPrinting details about the keys' prime numbers p and q:")
    print_private_key_details(private_key)  # Attempt to print p and q (though typically not supported)

    # Prompt the user for a plaintext input
    message = input("\nPlaintext inputs: ")
    
    # Encrypt the message and print the ciphertext
    encrypted = encrypt_message(message, public_key)
    
    # Decrypt the encrypted message to verify the output
    decrypted = decrypt_message(encrypted, private_key)
    print("\nDecrypted message (should match plaintext inputs):", decrypted)
    
    # Sign the message and verify the signature
    signature = sign_message(message, private_key)
    
    # Verify the digital signature to check authenticity
    verification = verify_signature(message, signature, public_key)
    print("\nSignature verified (True indicates authenticity and integrity):", verification)

if __name__ == "__main__":
    main()
