from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
import os

# Example: AES Encryption
key = os.urandom(32)
cipher = Cipher(algorithms.AES(key), modes.CFB(b'16bytesiv123456'))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"My secret message") + encryptor.finalize()

print("Encrypted:", ciphertext)
