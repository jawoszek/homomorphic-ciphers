import collections
from random import getrandbits

Encryption = collections.namedtuple('Encryption', ['L', 'N', 'P', 'Q', 'p'])
SumResult = collections.namedtuple('SumResult', ['value', 'carryover'])


def generate_encryption(L):
    return Encryption(L, L, L**2, L**5, generate_secret_key(L**2))


def generate_secret_key(P):
    return 2*getrandbits(P-1) + 1


def transform_bits(m, n, transformation):
    output = []
    m_t = m
    for _ in range(0, n):
        value = m_t % 2
        transformed_value = transformation(value)
        output.append(transformed_value)
        m_t = m_t >> 1
    return output


def transform_to_bits(m, transformation):
    output = 0
    for i in range(0, len(m)):
        output += transformation(m[i])*(2**i)
    return output


def encrypt(m, encryption):
    def transform(value):
        return encrypt_bit(value, encryption)
    return transform_bits(m, encryption.N, transform)


def encrypt_bit(m, encryption):
    m_prime = m + 2*getrandbits(encryption.N-1)
    return m_prime + encryption.p*getrandbits(encryption.Q)


def decrypt(c, encryption):
    def transform(value):
        return decrypt_bit(value, encryption)
    return transform_to_bits(c, transform)


def decrypt_bit(c, encryption):
    return (c % encryption.p) % 2


def cipher_not(c):
    return c + 1


def cipher_and(c1, c2):
    return c1 * c2


def cipher_xor(c1, c2):
    return c1 + c2


def cipher_or(c1, c2):
    return cipher_not(cipher_and(cipher_not(c1), cipher_not(c2)))


def sum_ciphers(c1, c2, c3):
    value = cipher_xor(cipher_xor(c1, c2), c3)
    carryover = cipher_or(
        cipher_and(c1, c2),
        cipher_and(cipher_or(c1, c2), c3)
    )
    return SumResult(value=value, carryover=carryover)


def sum_encrypted(encrypted1, encrypted2):
    output = []
    previous_carryover = 0
    length = max(len(encrypted1), len(encrypted2))
    for i in range(0, length):
        c1 = encrypted1[i]
        c2 = encrypted2[i]
        value, previous_carryover = sum_ciphers(c1, c2, previous_carryover)
        output.append(value)
    output.append(previous_carryover)
    return output
