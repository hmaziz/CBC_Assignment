from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from task1 import cbc_encrypt, cbc_decrypt, generate_key_iv
from urllib.parse import quote, unquote
BLOCK_SIZE_BYTES = 16


def url_encode(text):
    return quote(text)

def url_decode(text):
    return unquote(text)

def submit(user_input, key, iv):
    modified_input = f"userid=456;userdata={user_input};session-id=31337"
    modified_input = modified_input.replace(';', '%3B').replace('=', '%3D')
    encrypted_data = cbc_encrypt(modified_input.encode(), key, iv)
    return encrypted_data

def verify(encrypted_data, key, iv):
    decrypted_data = cbc_decrypt(encrypted_data, key, iv)
    return b";admin=true;" in decrypted_data # checking for specific pattern we want to find in the decrypted string

# Library Function not in use, used to validate implemented encryption function which is working.
# def decrypt_aes_cbc_library(ciphertext, key, iv):
#     decryptor = Cipher(
#         algorithms.AES(key),
#         modes.CBC(iv),
#         backend=default_backend()
#     ).decryptor()
#     padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#     unpadder = padding.PKCS7(128).unpadder()
#     plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

#     return plaintext

# def main():
#     key, iv = generate_key_iv()  # Generate key and IV

#     # Block of data that will decrypt to all zeros
#     zero_block = "\x00" * BLOCK_SIZE_BYTES

#     admin_string = ";admin=true;"
#     padded_admin_string = admin_string.ljust(BLOCK_SIZE_BYTES, '\x00')

#     encrypted_data = submit(zero_block + padded_admin_string, key, iv)
#     encrypted_data = bytearray(encrypted_data)

#     # Calculate the index where the zero block is located in the ciphertext
#     block_index = BLOCK_SIZE_BYTES  # The zero block is the first block after the IV
#     flip_index = block_index - BLOCK_SIZE_BYTES

#     # Creating a mask for the bit-flipping attack by XORing the target 
#     # The mask will flip the corresponding bits in the block after the zero block when decrypted
#     mask = bytearray([0] * BLOCK_SIZE_BYTES)
#     for i, char in enumerate(admin_string):
#         mask[i] = ord(char) ^ encrypted_data[block_index + i] ^ ord(zero_block[i])

#     # need to apply mask before 0 block of string
#     for i in range(len(mask)):
#         encrypted_data[flip_index + i] ^= mask[i]
#     is_pattern_present = verify(bytes(encrypted_data), key, iv)
#     print(f"Pattern Found: {is_pattern_present}")
#     decrypted_data = cbc_decrypt(bytes(encrypted_data), key, iv)
#     print(f"Decrypted data: {decrypted_data}")

# if __name__ == "__main__":
#     main()


def main():
    key, iv = generate_key_iv()  # Generate key and IV
    user_string = "You’re the man now, dog"
    encrypted_data = submit(user_string, key, iv)
    # print(f"Encrypted data: {encrypted_data}")

    modified_encrypted_data = bytearray(encrypted_data)
    modified_encrypted_data[BLOCK_SIZE_BYTES - 1] ^= 1  

    is_pattern_present = verify(modified_encrypted_data, key, iv)
    print(f"Pattern Found: {is_pattern_present}")
    decrypted_data = cbc_decrypt(modified_encrypted_data, key, iv)
    # print(f"Decrypted data: {decrypted_data}")




if __name__ == "__main__":
    main()
