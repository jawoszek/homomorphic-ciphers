import unittest

from crypto.somewhat_homomorphic import generate_encryption, encrypt, decrypt, sum_encrypted


class TestSomewhatHomomorphic(unittest.TestCase):
    def test_simple_addition(self):
        input_value_1 = 84
        input_value_2 = 69
        encryption = generate_encryption(10)

        encrypted_value_1 = encrypt(input_value_1, encryption)
        decrypted_value_1 = decrypt(encrypted_value_1, encryption)

        encrypted_value_2 = encrypt(input_value_2, encryption)
        decrypted_value_2 = decrypt(encrypted_value_2, encryption)

        encrypted_sum = sum_encrypted(encrypted_value_1, encrypted_value_2)
        decrypted_sum = decrypt(encrypted_sum, encryption)
        self.assertEqual(
            decrypted_sum,
            input_value_1 + input_value_2,
            decrypted_value_1 + decrypted_value_2
        )


if __name__ == '__main__':
    unittest.main()
