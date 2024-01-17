import hmac
import struct
import math
from hashlib import sha1, sha256, sha384

def sha1_prf(K, A, B, length):
    """
    References:
        IEEE 802.11-2020 standard
            Sub-clause 12.7.1.2 - PRF
    """
    i = 0
    R = b''
    while i <= math.ceil((length * 8) / 160):
        hmacsha1 = hmac.new(K, A + chr(0).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:length]

def sha256_kdf(K, label, context, length):
    """
    References:
        IEEE 802.11-2020 standard
            Sub-clause 12.7.1.6.2 - Key derivation function (KDF)
    """
    i = 1
    result = b''
    while i <= math.ceil((length * 8) / 256):
        hmacsha256 = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), sha256)
        result = result + hmacsha256.digest()
        i += 1
    return result[0:length]

def sha384_kdf(K, label, context, length):
    """
    References:
        IEEE 802.11-2020 standard
            Sub-clause 12.7.1.6.2 - Key derivation function (KDF)
    """
    i = 1
    result = b''
    while i <= math.ceil((length * 8) / 384):
        hmacsha384 = hmac.new(K, struct.pack('<H', i) + label + context + struct.pack('<H', (length * 8)), sha384)
        result = result + hmacsha384.digest()
        i += 1
    return result[0:length]