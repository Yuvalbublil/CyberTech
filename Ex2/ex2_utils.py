from Crypto.Util import number
import numpy as np
import base64


PRIME_NUMBER_BITS = 13  # If your code is running too slow, make it 9
N_MAX_BITS = PRIME_NUMBER_BITS * 2
MAX_CBC_KEY_POWER = (PRIME_NUMBER_BITS - 1) * 2
MAX_CBC_KEY = np.power(2, MAX_CBC_KEY_POWER)
BLOCK_SIZE = MAX_CBC_KEY_POWER // 8
INITIAL_VECTOR = b"0" * BLOCK_SIZE


def get_random_prime():
    """
    Used for key-generation
    @return a random large prime number.
    """
    return number.getPrime(PRIME_NUMBER_BITS)


def egcd(a, b):
    """
    Euclid's expanded algorithm for determining the greatest common divisor
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def get_multiplicative_inverse(a, m):
    """
    Returns the multiplicative inverse of a under modulo m.
    @param a the number we wish to find the inverse of
    @param m the modulo to use.
    @return b, such that (a * b) % m = 1.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def gcd(a, b):
    """
    Euclid's algorithm for determining the greatest common divisor
    @param a
    @param b
    @return greatesr common divisor of a and b. If it is 1 they are coprime.
    """
    while b != 0:
        a, b = b, a % b
    return a


def is_coprime(a, b):
    """
    Checks that a and b are coprime.
    @param a
    @param b
    @return True if coprime, False otherwise.
    """
    return (gcd(a, b) == 1)


def xor_bytes(b1, b2):
    """
    Computes xor on two EQUALLY SIZED byte arrays
    @param s1 first string
    @param s2 second string
    @return s1 XOR s2
    """
    return bytes(a ^ b for (a, b) in zip(b1, b2))


def int_2_bytes(num, length):
    """
    Translates an integer to it's bytes
    @param num number to translate
    @param length the amount of bytes the number is, which will be the length of the returned string
    @return the representation of the number's bytes.
    """
    hex_rep = hex(num)[2:]
    hex_rep = '0' * (len(hex_rep) % 2) + hex_rep # Pad to even
    hex_rep = '0' * 2 * (length - (len(hex_rep) // 2)) + hex_rep
    bytes_ascii = ""

    for i in range(0, len(hex_rep), 2):
        bytes_ascii += chr(int(hex_rep[i:i+2], 16))

    return bytes_ascii.encode()


class InvalidSignatureError(Exception):
    """
    Raise this when the signauture of the encryption is invalid.
    """
    pass


class InvalidPayloadLengthError(Exception):
    """
    Raise this when the length of the payload is not divisable by KEY_BYTES
    """
    pass


if __name__ == '__main__':
    print("Example usage of ex2_utils.py:")
    print(f"Max CBC is {MAX_CBC_KEY}, which is {BLOCK_SIZE} bytes long, and the IV is {INITIAL_VECTOR}")
    print(f"Random primes: {get_random_prime()}, {get_random_prime()}, {get_random_prime()}")
    print(f"Is coprime: for (7, 5) {is_coprime(5, 7)}, for (7, 21) {is_coprime(7, 21)}")
    print(f"Multiplicative inverse of 22609 under modulo 28836: {get_multiplicative_inverse(22609, 28836)}")
    print(f"Xor of '111' and 'qrs': {xor_strings('111', 'qrs')}")
    print(f"Int2str of 4 bytes for 0x61626364 (hexadecimal for abcd): {int_2_str(0x61626364, 4)}")
    print(f"Str2Int(int2str) of 4 bytes for 0x61626364 (hexadecimal for abcd): {hex(str_2_int(int_2_str(0x61626364, 4)))}")
    print(f"Encode base64 of abc: {str_2_base64('abc')}")
    print(f"Decode base64 for abc: {base64_2_str(str_2_base64('abc'))}")
