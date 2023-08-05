"""
python3 -m unittest tests/test_gen_msk.py
"""

import unittest
from gen_msk import xor_bits
from gen_msk import decrypt_mppe_key


test_radius_shared_secret = 'radiussharedsecret'
test_encrypted_ms_mppe_recv_key = '94f77e05a8610c7a2186f1a4d8d6fa328192619455dee03142669e1a1ff583b3593284d31c985edc78892a0414e54e527d55'
test_encrypted_ms_mppe_send_key = '9d662d78d01092890b516531291542373db99da21ac9d8f58d8e2583318486a911c7edfe7f17457f81c6a4169948936dabe4'
test_request_authenticator = 'a0fcd2bd28f624724726135fc97d22d9'

decrypted_ms_mppe_recv_key = '7dca16f8d83d5d34d39034654c9bd84cc57beae90c7639b0291b7e0846b9dffa'
decrypted_ms_mppe_send_key = '501097cddf665fccfac7933504e86325461ded33ba080066ab1d6ed314950c58'


class TestGenMskFunctions(unittest.TestCase):

    def test_xor_bits(self):
        test1_bytes1 = bytes.fromhex('11111111')
        test1_bytes2 = bytes.fromhex('10101010')
        test1_result = xor_bits(test1_bytes1, test1_bytes2)
        self.assertIsInstance(test1_result, bytes)
        self.assertEqual(len(test1_result), 4)
        self.assertEqual(test1_result.hex(), '01010101')

        test2_bytes1 = bytes.fromhex('1111111111111111')
        test2_bytes2 = bytes.fromhex('10101010')
        test2_result = xor_bits(test2_bytes1, test2_bytes2)
        self.assertIsInstance(test2_result, bytes)
        self.assertEqual(len(test2_result), 8)
        self.assertEqual(test2_result.hex(), '1111111101010101')

    def test_decrypt_mppe_key(self):
        radius_shared_secret = bytes(test_radius_shared_secret, "ascii")
        encrypted_ms_mppe_recv_key = bytes.fromhex(test_encrypted_ms_mppe_recv_key)
        encrypted_ms_mppe_send_key = bytes.fromhex(test_encrypted_ms_mppe_send_key)
        request_authenticator = bytes.fromhex(test_request_authenticator)

        recv_key_result = decrypt_mppe_key(
            radius_shared_secret, encrypted_ms_mppe_recv_key, request_authenticator
        )
        self.assertIsInstance(recv_key_result, bytes)
        self.assertEqual(len(recv_key_result), 32)
        self.assertEqual(recv_key_result.hex(), decrypted_ms_mppe_recv_key)

        send_key_result = decrypt_mppe_key(
            radius_shared_secret, encrypted_ms_mppe_send_key, request_authenticator
        )
        self.assertIsInstance(send_key_result, bytes)
        self.assertEqual(len(send_key_result), 32)
        self.assertEqual(send_key_result.hex(), decrypted_ms_mppe_send_key)


if __name__ == '__main__':
    unittest.main()