import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class FileEncryptor:
    KEY_SIZE = 32
    BLOCK_SIZE = 16

    def encrypt(self, data: bytes):
        key = get_random_bytes(self.KEY_SIZE)
        iv = get_random_bytes(self.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, self.BLOCK_SIZE))
        return encrypted_data, key.hex(), iv.hex()

    def decrypt(self, encrypted_data: bytes, key_hex: str, iv_hex: str):
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), self.BLOCK_SIZE)
