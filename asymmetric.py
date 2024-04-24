import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
    return decrypted_message

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_with_private_key(message, private_key):
    encrypted_message = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return encrypted_message

def decrypt_with_public_key(encrypted_message, public_key):
    try:
        decrypted_message = public_key.verify(
            encrypted_message,
            b'',  # Empty bytes since we don't need a message for verification
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return decrypted_message.decode()
    except InvalidSignature:
        return "Error: Invalid signature. The message could not be decrypted."


def hash_message(message):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    return hashed_message

def main():
    while True:
        print("\nMenu:")
        print("1. Encrypt and Decrypt a Message")
        print("2. Encrypt and Store Personal Information")
        print("3. Asymmetric Encryption with Private and Public Key")
        print("4. Hashing Algorithm")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            key = generate_key()
            encrypted_message = encrypt_message(message, key)
            print("Encrypted Message:", encrypted_message)
            decrypted_message = decrypt_message(encrypted_message, key)
            if decrypted_message:
                print("Decrypted Message:", decrypted_message)
            else:
                print("Decryption failed.")

        elif choice == '2':
            first_name = input("Enter your first name: ")
            last_name = input("Enter your last name: ")
            id_number = input("Enter your ID number: ")
            personal_info = f"{first_name} {last_name}, ID: {id_number}"
            key = generate_key()
            encrypted_info = encrypt_message(personal_info, key)
            print("Encrypted Personal Information:", encrypted_info)

        elif choice == '3':
            private_key, public_key = generate_rsa_keys()
            message = input("Enter the message to encrypt: ")
            encrypted_message = encrypt_with_private_key(message, private_key)
            print("Encrypted Message:", encrypted_message)
            decrypted_message = decrypt_with_public_key(encrypted_message, public_key)
            if decrypted_message:
                print("Decrypted Message:", decrypted_message)
            else:
                print("Decryption failed.")

        elif choice == '4':
            message = input("Enter the message to hash: ")
            hashed_message = hash_message(message)
            print("Hashed Message:", hashed_message)

        elif choice == '5':
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()

