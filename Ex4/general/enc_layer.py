from general.enc_utils import get_random_prime, get_multiplicative_inverse, is_coprime, \
    int_2_bytes, xor_bytes, \
    MAX_CBC_KEY, BLOCK_SIZE, INITIAL_VECTOR, \
    InvalidSignatureError, InvalidPayloadLengthError

import numpy as np
import json
import base64
from typing import Tuple

ENCODING = 'utf-8'

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
    while q == p:
        q = get_random_prime()
        p = get_random_prime()
    n = q * p
    sigma = (p - 1) * (q - 1)
    e = 65537
    while not is_coprime(e, sigma):
        e = np.random.randint(3, sigma)
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
    e, n = key
    e_bin = bin(e)[2:]
    A = e.bit_length()
    m_mod_array = [num % n]
    # m_mod_array.append(num % n)
    for _ in range(1, A):
        m_mod_array.append((np.int64(m_mod_array[-1]) * np.int64(m_mod_array[-1])) % n)
    m_mod_array = m_mod_array[::-1]
    summery = np.int64(1)
    for i in range(A):
        if e_bin[i] == '1':
            summery = (m_mod_array[i] * np.int64(summery)) % n

    return int(summery)

def cbc_encrypt(data: bytes, key: int) -> bytes:
    """
    Encrypts data using CBC encryption. Use INITIAL_VECTOR for IV.
    @param data the data to encrypt.
    @param key the key to use for encryption.
    @return encrypted CBC data. DO NOT RETURN THE INITIAL_VECTOR BLOCK.
    """
    key_bytes = int_2_bytes(key, BLOCK_SIZE)  # Get the string of the key
    blocks = [INITIAL_VECTOR]  # The first block in the CBC is the INITIAL_VECTOR
    array = bytearray()
    block = blocks[0]
    for i in range(len(data) // BLOCK_SIZE + 1):
        block = xor_bytes(block, data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE])
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
    for i in range((len(data) // BLOCK_SIZE) + 1):
        temp = xor_bytes(data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE], key_bytes)  # the Block Cipher Encryption
        temp = xor_bytes(temp, block)
        block = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        data_array.extend(temp)
    return bytes(data_array)


def advance_encrypt(data: bytes, key: int) -> bytes:
    """
    Encrypts data using CBC encryption. Use INITIAL_VECTOR for IV.
    @param data the data to encrypt.
    @param key the key to use for encryption.
    @return encrypted CBC data. DO NOT RETURN THE INITIAL_VECTOR BLOCK.
    """

    def block_cipher_enc(in_block: bytes, in_key: int) -> bytes:
        a = bytearray(xor_bytes(in_block, in_key))
        flag = False
        if len(a) % 2 == 1:
            flag = True
        b = bytearray()
        for i in range(len(a) // 2):
            b.append(a[2 * i + 1])
            b.append(a[2 * i])
        if flag:
            b.append(a[-1])
        return bytes(b)

    key_bytes = int_2_bytes(key, BLOCK_SIZE)  # Get the string of the key
    blocks = [INITIAL_VECTOR]  # The first block in the CBC is the INITIAL_VECTOR

    array = bytearray()
    block = blocks[0]
    for i in range(len(data) // BLOCK_SIZE + 1):
        block = xor_bytes(block, data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE])
        block = block_cipher_enc(block, key_bytes)  # the Block Cipher Encryption
        array.extend(block)
    return bytes(array)


def advance_decrypt(enc_data: bytes, key: int) -> bytes:
    """
    Decrypts data using CBC encryption. Use INITIAL_VECTOR for IV.
    @param enc_data the data to decrypt.
    @param key the key to use for decryption.
    @return decrypted plain data.
    """
    def block_cipher_dec(in_block: bytes, in_key: int) -> bytes:
        a: bytearray = bytearray(in_block)
        flag = False
        if len(a) % 2 == 1:
            flag = True
        b: bytearray = bytearray()
        for i in range(len(a) // 2):
            b.append(a[2 * i + 1])
            b.append(a[2 * i])
        if flag:
            b.append(a[-1])
        return xor_bytes(bytes(b), in_key)

    key_bytes = int_2_bytes(key, BLOCK_SIZE)  # Get the string of the key
    block = INITIAL_VECTOR  # The first block in the CBC is the INITIAL_VECTOR
    data = enc_data
    data_array = bytearray()
    for i in range((len(data) // BLOCK_SIZE) + 1):
        temp = block_cipher_dec(data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE], key_bytes)  # the Block Cipher Encryption
        temp = xor_bytes(temp, block)
        block = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        data_array.extend(temp)
    return bytes(data_array)


def _pad_and_encrypt(data: bytes, key: int) -> bytes:
    pad_size = (BLOCK_SIZE - len(data) % BLOCK_SIZE) % BLOCK_SIZE  # this is calculate the number of bytes we need.
    number_of_pads = pad_size // len(bytes(PADDER, ENCODING))  # number of padders needed
    data_array = bytearray(X_VALIDITY * (BLOCK_SIZE // len(bytes(X_VALIDITY, ENCODING))), ENCODING)
    data_array.extend(bytearray(PADDER * number_of_pads, ENCODING))
    data_array.extend(data)
    assert (len(data_array) % BLOCK_SIZE == 0)
    return cbc_encrypt(data_array, key)


def encrypt_data(data: str, pub_key: KEY) -> bytes:
    """
    Encrypts the data using the algorithm specified.
    @param data raw data to encrypt. The data is given as text.
    @param pub_key public key to encrypt with.
    @return string representing JSON dump of the encryption dictionary. The returned data is in binary.
    """
    # Your code here...
    cbc_key = np.random.randint(1, MAX_CBC_KEY)
    enc_data = _pad_and_encrypt(bytes(data, ENCODING), cbc_key)
    enc_cbc_key = use_key(cbc_key, pub_key)
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
    try:
        assert (len(payload) % BLOCK_SIZE == 0)
    except AssertionError:
        raise InvalidPayloadLengthError

    enc_cbc_key = enc_dict["enc_key"]
    cbc_key = use_key(enc_cbc_key, pub_key)
    data_with_padding: bytes = cbc_decrypt(payload, cbc_key)
    validity_block = data_with_padding[0:BLOCK_SIZE].decode(ENCODING)
    for i in range(len(validity_block)):
        if validity_block[i] != X_VALIDITY:
            raise InvalidSignatureError
    string_with_padding = data_with_padding[BLOCK_SIZE:].decode(ENCODING)
    for i in range(len(string_with_padding)):
        if string_with_padding[i] != PADDER:
            return string_with_padding[i:]


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

    print("CBC encrypt of abcdef with key 17:", advance_encrypt("abcdef".encode(), 17))
    print("CBC decrypt of previous encryption:",
          advance_decrypt(advance_encrypt("abcdef".encode(), 17), 17))  # Should be abcdef
    print()

    data = "Awesome raw data!!1"
    print("Data:", data)
    e = encrypt_data(data, pub)
    print("Enc:", e)
    d = decrypt_and_validate_data(e, pri)
    print("Dec:", d)  # Should be the original data
