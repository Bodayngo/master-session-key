"""
python3 -m unittest tests/test_gen_pmkid.py
"""

import unittest
from passphrase_to_psk import calculate_psk


test_ssid = 'IEEE'
test_passphrase = 'password'

psk = 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e'


class TestPassphraseToPskFunctions(unittest.TestCase):

    def test_calculate_psk(self):
        psk_result = calculate_psk(test_passphrase, test_ssid)
        self.assertIsInstance(psk_result, bytes)
        self.assertEqual(len(psk_result), 32)
        self.assertEqual(psk_result.hex(), psk)


if __name__ == '__main__':
    unittest.main()