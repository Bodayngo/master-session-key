import hmac
import struct
import math
from hashlib import sha1, sha256, sha384

def sha1_prf(K, A, B, length):
    """
    PTK = PRF-X(PMK, "Pairwise key expansion",
            Min(AA, SA) || Max(AA, SA) ||
            Min(ANonce, SNonce) || Max(ANonce, SNonce))

    Input:
        K (bytes): Key used for PRF
            PMK when using PRF to derive PTK, for example
        A (bytes): Unique label for each different purpose of the PRF 
            "Pairwise key expansion" when using PRF to derive PTK, for example
        B (bytes): Variable length string
            "min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)" when using PRF to derive PTK, for example
    """
    i = 0
    R = b''
    while i <= math.ceil((length * 8) / 160):
        hmacsha1 = hmac.new(K, A + chr(0).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:length]

def sha256_kdf(K, label, context, length):
    i = 1
    result = b''
    while i <= math.ceil((length * 8) / 256):
        hmacsha256 = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), sha256)
        result = result + hmacsha256.digest()
        i += 1
    return result[0:length]

def sha384_kdf(K, label, context, length):
    i = 1
    result = b''
    while i <= math.ceil((length * 8) / 384):
        hmacsha384 = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), sha384)
        result = result + hmacsha384.digest()
        i += 1
    return result[0:length]