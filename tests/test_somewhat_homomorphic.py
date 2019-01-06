import unittest

from crypto.somewhat_homomorphic import generate_encryption, encrypt, decrypt, sum_encrypted


class TestSomewhatHomomorphic(unittest.TestCase):

    def test_decryption(self):
        for value, param in [(0, 2), (1, 4), (2, 4), (5, 6), (8, 6), (14, 6),
                             (17, 8), (42, 10), (67, 10)]:
            with self.subTest(input_value=value):
                encryption = generate_encryption(param)
                self.assertEqual(
                    decrypt(encrypt(value, encryption), encryption),
                    value
                )

    def test_simple_addition(self):
        for input_1, input_2, param in [(1, 1, 10), (84, 69, 16)]:
            with self.subTest(input_1=input_1, input_2=input_2):
                encryption = generate_encryption(param)

                encrypted_1 = encrypt(input_1, encryption)
                decrypted_1 = decrypt(encrypted_1, encryption)

                encrypted_2 = encrypt(input_2, encryption)
                decrypted_2 = decrypt(encrypted_2, encryption)

                encrypted_sum = sum_encrypted(encrypted_1, encrypted_2)
                decrypted_sum = decrypt(encrypted_sum, encryption)
                self.assertEqual(
                    input_1 + input_2,
                    decrypted_1 + decrypted_2,
                    decrypted_sum
                )


if __name__ == '__main__':
    unittest.main()
