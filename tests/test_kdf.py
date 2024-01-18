import unittest
from src.kdf import *

sha1_prf_pmk = bytes.fromhex('8b470d911a0428b393a8396d3e0faa69d994d87f682d293c460f8262a5cbbcb1')
sha1_prf_anonce = bytes.fromhex('13474349c681499192f7f6581121b8e60c166925fac52cc29e5d03d5a1e4acf3')
sha1_prf_snonce = bytes.fromhex('5d13d1569b435213f9724003655882a4d6d713a894ecd00db13ce46d8f11e960')
sha1_prf_spa = bytes.fromhex('2429348bb466')
sha1_prf_aa = bytes.fromhex('c29c2ee79b80')
sha1_prf_kck = '0c18b0dfda634acd02ff19138b6018dd'
sha1_prf_kek = '4fc9280a6833fdd9dde5c302222c2fc4'
sha1_prf_tk = 'ac3c0c7e2ba97c718cc5dde645e672ea'

sha256_kdf_pmk = bytes.fromhex('bf9721e26479f2a412dee0e89a4fef1894c3feceab36d53c6583ce96e3c7b2e5')
sha256_kdf_anonce = bytes.fromhex('5417cde51869ebc00200d6ac2e43ea4d774de9aadceb438383beaf696f1601e3')
sha256_kdf_snonce = bytes.fromhex('27d0029a0464fdac4c1870740d138c504be995a4e384a5a826ee539a2df5fe7f')
sha256_kdf_aa = bytes.fromhex('c29c2ee79b80')
sha256_kdf_spa = bytes.fromhex('8045dd31c4c8')
sha256_kdf_kck = '9464f0b1681cb18863edcb0eef087ad8'
sha256_kdf_kek = '206e1a8bfa66ad7f0fd9a63b7b3e31df'
sha256_kdf_tk = 'ec7e2f6ef92b17c9df75007b8a4d437f'

sha384_kdf_pmk = bytes.fromhex('8bf26829f546c3bb66890da1fc7b0f7e3863f70a41abccd50c735fbc090863fa61639bbb3dd616c3172d068cc0188edd')
sha384_kdf_anonce = bytes.fromhex('5c4d0eb6835565c3dc7ee4f8f36193282041a27faf9dc8dbbbc7f16eee627cd0')
sha384_kdf_snonce = bytes.fromhex('1ec0830d02bc8a70044ea182a12b88605fcc58495b233092fa8ba119fb94c388')
sha384_kdf_aa = bytes.fromhex('c29c2ee79b80')
sha384_kdf_spa = bytes.fromhex('8045dd31c4c8')
sha384_kdf_kck = '2c7aaab3991bd283ba0d5bf830206010eeed382c945c9301'
sha384_kdf_kek = 'b6ea093b60f94f90ae11f26a0f2ba4a2fa10f0ad9a8fd26657ca5b5e1348f0f0'
sha384_kdf_tk = '7091d35e275bf0866fbfcf9be7741c954bc811296f750103873a6e73fa9bd274'

def getAB(anonce, snonce, aa, spa):
    A = b'Pairwise key expansion'
    B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return A, B

class TestKDFFunctions(unittest.TestCase):

    def test_sha1_prf(self):
        A, B = getAB(sha1_prf_anonce, sha1_prf_snonce, sha1_prf_aa, sha1_prf_spa)
        ptk = sha1_prf(sha1_prf_pmk, A, B, 48)
        kck = ptk[0:16]
        kek = ptk[16:32]
        tk = ptk[32:48]
        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 48)
        self.assertEqual(len(kck), 16)
        self.assertEqual(len(kek), 16)
        self.assertEqual(len(tk), 16)
        self.assertEqual(kck.hex(), sha1_prf_kck)
        self.assertEqual(kek.hex(), sha1_prf_kek)
        self.assertEqual(tk.hex(), sha1_prf_tk)

    def test_sha256_kdf(self):
        A, B = getAB(sha256_kdf_anonce, sha256_kdf_snonce, sha256_kdf_aa, sha256_kdf_spa)
        ptk = sha256_kdf(sha256_kdf_pmk, A, B, 48)
        kck = ptk[0:16]
        kek = ptk[16:32]
        tk = ptk[32:48]
        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 48)
        self.assertEqual(len(kck), 16)
        self.assertEqual(len(kek), 16)
        self.assertEqual(len(tk), 16)
        self.assertEqual(kck.hex(), sha256_kdf_kck)
        self.assertEqual(kek.hex(), sha256_kdf_kek)
        self.assertEqual(tk.hex(), sha256_kdf_tk)

    def test_sha384_kdf(self):
        A, B = getAB(sha384_kdf_anonce, sha384_kdf_snonce, sha384_kdf_aa, sha384_kdf_spa)
        ptk = sha384_kdf(sha384_kdf_pmk, A, B, 88)
        kck = ptk[0:24]
        kek = ptk[24:56]
        tk = ptk[56:88]
        self.assertIsInstance(ptk, bytes)
        self.assertEqual(len(ptk), 88)
        self.assertEqual(len(kck), 24)
        self.assertEqual(len(kek), 32)
        self.assertEqual(len(tk), 32)
        self.assertEqual(kck.hex(), sha384_kdf_kck)
        self.assertEqual(kek.hex(), sha384_kdf_kek)
        self.assertEqual(tk.hex(), sha384_kdf_tk)


if __name__ == '__main__':
    unittest.main()