from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class EncryptionUtils:
    BLOCK_SIZE = 16

    # Pads the input data
    @staticmethod
    def pad(data: bytes) -> bytes:
        pad_len = EncryptionUtils.BLOCK_SIZE - (len(data) % EncryptionUtils.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    # Unpads the input data
    @staticmethod
    def unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    # Encrypts the input data with AES
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        enc = cipher.encryptor()
        padded = EncryptionUtils.pad(data)
        return enc.update(padded) + enc.finalize()

    # Decrypts the input data with AES
    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        dec = cipher.decryptor()
        out = dec.update(data) + dec.finalize()
        return EncryptionUtils.unpad(out)
