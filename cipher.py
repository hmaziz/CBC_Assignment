from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants
BLOCK_SIZE_BYTES = 16
MAX_BLOCKSIZE_BITS = 2040

# Utility functions
def _validate_blocksize(blocksize_bits):
    if blocksize_bits > MAX_BLOCKSIZE_BITS:
        raise ValueError(f"Blocksize too large: {blocksize_bits}")
    if blocksize_bits % 8 != 0:
        raise ValueError(f"Blocksize not divisible by 8: {blocksize_bits % 8}")

def _pad_pkcs7(data_bytes, blocksize_bytes):
    padding_length = blocksize_bytes - (len(data_bytes) % blocksize_bytes)
    padding_length = padding_length if padding_length else blocksize_bytes
    return data_bytes + bytes([padding_length] * padding_length)

def _strip_pkcs7(padded_data):
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

# AES Encryption/Decryption functions
def _aes128_operation(data, key, mode):
    if len(data) != BLOCK_SIZE_BYTES or len(key) != BLOCK_SIZE_BYTES:
        raise ValueError("AES128 requires 128-bit data and key sizes")

    cipher = Cipher(algorithms.AES(key), mode)
    operator = cipher.encryptor() if mode == modes.ECB() else cipher.decryptor()
    return operator.update(data) + operator.finalize()

def _aes128_encrypt(data, key):
    return _aes128_operation(data, key, modes.ECB())

def _aes128_decrypt(data, key):
    return _aes128_operation(data, key, modes.ECB())

# ECB Mode functions
def ecb_encrypt(data, key):
    padded_data = _pad_pkcs7(data, BLOCK_SIZE_BYTES)
    return b"".join(_aes128_encrypt(padded_data[i:i+BLOCK_SIZE_BYTES], key) for i in range(0, len(padded_data), BLOCK_SIZE_BYTES))

def ecb_decrypt(data, key):
    decrypted_data = b"".join(_aes128_decrypt(data[i:i+BLOCK_SIZE_BYTES], key) for i in range(0, len(data), BLOCK_SIZE_BYTES))
    return _strip_pkcs7(decrypted_data)

# CBC Mode functions
def cbc_encrypt(data, key, iv):
    padded_data = _pad_pkcs7(data, BLOCK_SIZE_BYTES)
    encrypted_blocks = []
    iv_next = iv
    for i in range(0, len(padded_data), BLOCK_SIZE_BYTES):
        block = bytes(a ^ b for a, b in zip(padded_data[i:i+BLOCK_SIZE_BYTES], iv_next))
        iv_next = _aes128_encrypt(block, key)
        encrypted_blocks.append(iv_next)
    return b"".join(encrypted_blocks)

def cbc_decrypt(data, key, iv):
    decrypted_blocks = []
    for i in reversed(range(BLOCK_SIZE_BYTES, len(data), BLOCK_SIZE_BYTES)):
        block = _aes128_decrypt(data[i:i+BLOCK_SIZE_BYTES], key)
        decrypted_blocks.append(bytes(a ^ b for a, b in zip(block, data[i-BLOCK_SIZE_BYTES:i])))
    final_block = _aes128_decrypt(data[:BLOCK_SIZE_BYTES], key)
    decrypted_blocks.append(bytes(a ^ b for a, b in zip(final_block, iv)))
    return _strip_pkcs7(b"".join(reversed(decrypted_blocks)))
