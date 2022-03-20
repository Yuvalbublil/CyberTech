from ex2_utils import get_random_prime, get_multiplicative_inverse, is_coprime, \
    int_2_bytes, xor_bytes, \
    MAX_CBC_KEY, BLOCK_SIZE, INITIAL_VECTOR, \
    InvalidSignatureError, InvalidPayloadLengthError

import numpy as np
import json
import base64
from typing import Tuple

X_VALIDITY = "X"

PADDER = '~'

E_POWER = 16

KEY = Tuple[int, int]
KEY_PAIR = Tuple[KEY, KEY]


def generate_key_pair() -> KEY_PAIR:
    """
    Generates a pair of asymmetric keys for the RSA algorithm.
    Reminder: The public key is the tuple (e, n),
              The private key is the tuple (d, n).
    @return Tuple of keys (pub_key, pri_key) to use.
    """
    q = get_random_prime()
    p = get_random_prime()
    n = q * p
    sigma = (p - 1) * (q - 1)
    e = 2 ** E_POWER + 1
    d = get_multiplicative_inverse(e, sigma)
    pub_key = (e, n)
    pri_key = (d, n)
    return pub_key, pri_key


def use_key(num: int, key: KEY) -> int:
    """
    Computes the RSA algorithm on the given number with the given key.
    This function is useful both for encrypting and decrypting, with both the private and public keys.
    @param data the data to use the key on. Could be either raw data or cipher text.
    @param key the key used on the data. Could be either the public or private key.
    """
    return (num ** key[0]) % key[1]


def cbc_encrypt(data: bytes, key: int) -> bytes:
    """
    Encrypts data using CBC encryption. Use INITIAL_VECTOR for IV.
    @param data the data to encrypt.
    @param key the key to use for encryption.
    @return encrypted CBC data. DO NOT RETURN THE INITIAL_VECTOR BLOCK.
    """
    key_bytes = int_2_bytes(key, BLOCK_SIZE)  # Get the string of the key
    blocks = [INITIAL_VECTOR]  # The first block in the CBC is the INITIAL_VECTOR

    pad_size = (BLOCK_SIZE - len(data) % BLOCK_SIZE) % BLOCK_SIZE  # this is calculate the number of bytes we need.
    number_of_padds = pad_size // len(bytes(PADDER, 'utf-8'))  # number of padders needed
    data_array = bytearray(X_VALIDITY * (BLOCK_SIZE // len(bytes(X_VALIDITY, 'utf-8'))), 'utf-8')
    data_array.extend(bytearray(PADDER * number_of_padds, 'utf-8'))
    data_array.extend(data)
    assert (len(data_array) % BLOCK_SIZE == 0)
    array = bytearray()
    block = blocks[0]
    for i in range(len(data_array) // BLOCK_SIZE + 1):
        block = xor_bytes(block, data_array[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE])
        block = xor_bytes(block, key_bytes)  # the Block Cipher Encryption
        array.extend(block)
    return bytes(array)


def cbc_decrypt(enc_data: bytes, key: int) -> bytes:
    """
    Decrypts data using CBC encryption. Use INITIAL_VECTOR for IV.
    @param enc_data the data to decrypt.
    @param key the key to use for decryption.
    @return decrypted plain data.
    """
    key_bytes = int_2_bytes(key, BLOCK_SIZE)  # Get the string of the key
    block = INITIAL_VECTOR  # The first block in the CBC is the INITIAL_VECTOR
    data = enc_data
    data_array = bytearray()

    # assert (len(enc_data % BLOCK_SIZE == 0))

    for i in range((len(data) // BLOCK_SIZE) + 1):
        temp = xor_bytes(data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE], key_bytes)  # the Block Cipher Encryption
        temp = xor_bytes(temp, block)
        block = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        data_array.extend(temp)
    return bytes(data_array)

    # Your code here...


def encrypt_data(data: str, pub_key: KEY) -> bytes:
    """
    Encrypts the data using the algorithm specified.
    @param data raw data to encrypt. The data is given as text.
    @param pub_key public key to encrypt with.
    @return string representing JSON dump of the encryption dictionary. The returned data is in binary.
    """
    # Your code here...

    return json.dumps({
        "enc_key": enc_cbc_key,
        "payload": base64.b64encode(enc_data).decode()
    }).encode()


def decrypt_and_validate_data(data: bytes, pub_key: KEY) -> str:
    """
    Decrypts the data using the algorithm specified. Make sure the decrypted data starts with the
    proper signature, if not throw InvalidSignatureError. If the length of the payload
    (after decoding base64) is not divisable by BLOCK_SIZE, throw InvalidPayloadLengthError.
    @param data string representing JSON dump of the encryption dictionary. The data is in binary.
    @param pub_key public key to decrypt with
    @return decrypted data. The decrypted data should be returned as text.
    """
    enc_dict = json.loads(data.decode())
    payload = base64.b64decode(enc_dict["payload"])


if __name__ == '__main__':
    """
    Example main code you can use to run basic tests for your functions
    """
    pub, pri = generate_key_pair()
    print("Keys:", pub, pri)
    e = use_key(1000, pub)
    print("Use pub on 1000:", e)
    d = use_key(e, pri)
    print("Use pub and pri on 1000:", d)  # Encryption and decryption cancel out -> should be 1000
    print()

    print("CBC encrypt of abcdef with key 17:", cbc_encrypt("abcdef".encode(), 17))
    print("CBC decrypt of previous encryption:", cbc_decrypt(cbc_encrypt("abcdef".encode(), 17), 17)) # Should be abcdef
    print()
    #
    # data = "Awesome raw data!!1"
    # print("Data:", data)
    # e = encrypt_data(data, pub)
    # print("Enc:", e)
    # d = decrypt_and_validate_data(e, pri)
    # print("Dec:", d) # Should be the original data
