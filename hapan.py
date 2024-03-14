import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, key, key_size):
    cipher = Cipher(algorithms.AES(key), modes.CFB(key), backend=default_backend())

    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_file = f'encrypted_file_{key_size}_bits.txt'
    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    print(f"File encrypted with {key_size}-bit key. Encrypted file saved as {output_file}")
    print(f"Key used: {key}")
    print(f"Original plaintext: {plaintext}")
    print(f"Encrypted ciphertext: {ciphertext}")

def main():
    parser = argparse.ArgumentParser(description='Encrypt a file using AES algorithm.')
    parser.add_argument('file_path', help='Path to the file to be encrypted')
    parser.add_argument('key_size', type=int, choices=[128, 192, 256],
                        help='Key size for AES encryption (128, 192, or 256 bits)')
    parser.add_argument('--key', required=True, help='AES encryption key')
    args = parser.parse_args()

    # Validate the length of the key based on the key size
    if len(args.key.encode('ascii')) != args.key_size // 8:
        raise ValueError(f"Invalid key length for {args.key_size}-bit key.")

    encrypt_file(args.file_path, args.key.encode('ascii'), args.key_size)

if __name__ == "__main__":
    main()
