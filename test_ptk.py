from src.kdf import *

pmk = bytes.fromhex('bf9721e26479f2a412dee0e89a4fef1894c3feceab36d53c6583ce96e3c7b2e5')
anonce = bytes.fromhex('5417cde51869ebc00200d6ac2e43ea4d774de9aadceb438383beaf696f1601e3')
snonce = bytes.fromhex('27d0029a0464fdac4c1870740d138c504be995a4e384a5a826ee539a2df5fe7f')
aa = bytes.fromhex('c29c2ee79b80')
spa = bytes.fromhex('8045dd31c4c8')

def getAB(anonce, snonce, aa, spa):
    A = b'Pairwise key expansion'
    B = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return A, B

A, B = getAB(anonce, snonce, aa, spa)
ptk = sha256_kdf(pmk, A, B, 48)
kck = ptk[0:16] 
kek = ptk[16:32]
tk = ptk[32:48]
print(ptk.hex())
print(kck.hex())
print(kek.hex())
print(tk.hex())