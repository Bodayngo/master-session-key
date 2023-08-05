"""
python3 -m unittest tests/test_gen_pmkid.py
"""

import unittest
from gen_pmkid import calculate_pmkids


test_pmk = '03304a03fb68e904d47b78429d661f8bc7f373f5de6df640e9b0f3e142a6fe5d'
test_aa = 'AA:46:8D:00:50:20'
test_spa = '80:45:DD:31:C4:C8'

pmk_sha1 = '0db738755972d6a09cfadc3e235c9e29'
pmk_sha256 = '61eac9970bd64e1ca7820bfe9355b61b'
pmk_sha384 = '5c819340218a382d62959ae0d2ecb554'


class TestGenPmkidFunctions(unittest.TestCase):

    def test_calculate_pmkids(self):
        pmk = bytes.fromhex(test_pmk)
        spa = bytes.fromhex(test_spa.replace(":", "").replace("-", ""))
        aa = bytes.fromhex(test_aa.replace(":", "").replace("-", ""))
        pmk_sha1_result, pmk_sha256_result, pmk_sha384_result = calculate_pmkids(
            pmk, aa, spa
        )
        self.assertIsInstance(pmk_sha1_result, str)
        self.assertEqual(len(pmk_sha1_result), 32)
        self.assertEqual(pmk_sha1_result, pmk_sha1)

        self.assertIsInstance(pmk_sha256_result, str)
        self.assertEqual(len(pmk_sha256_result), 32)
        self.assertEqual(pmk_sha256_result, pmk_sha256)

        self.assertIsInstance(pmk_sha384_result, str)
        self.assertEqual(len(pmk_sha384_result), 32)
        self.assertEqual(pmk_sha384_result, pmk_sha384)


if __name__ == '__main__':
    unittest.main()