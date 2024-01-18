from src.kdf import sha256_kdf
import hashlib

test_client_mac = bytes.fromhex('8045dd31c4c8')
test_ap_mac = bytes.fromhex('c29c2ee79b80')
test_msk = bytes.fromhex('45c975e10ae6802545a1f23e98f0869c1bbf91308ce3459596f51066290b3ae81172746088d1c590b9dbe9f6ece159beadcd13d3d48b1245dfaff161686e5181')
test_ssid = b'Bodayngo-Test'
test_mdid = bytes.fromhex('674b')
test_r0khid = bytes.fromhex('43432d39432d33452d45372d39422d38303a76617033')
test_r1khid = bytes.fromhex('cc9c3ee79b80')
test_anonce = bytes.fromhex('be74076692e2f7b347b4a4904b1e1a4e801047e2abf5e5b763694dfe56c3cc9f')
test_snonce = bytes.fromhex('9cf84a9be99b7ffc44a45bad6b6a5034df956d0ac8a1b17e75c8936f2171719a')


def get_pmkr0(msk, aa, spa, ssid, mdid, r0khid, s0khid):
    """
    12.7.1.6.3 PMK-R0
        If the negotiated AKM is 00-0F-AC:3, then Q = 256 and
            - MPMK = L(MSK, 256, 256), i.e., the second 256 bits of the MSK
            - PMKID = Truncate-128(HMAC-SHA-256(MPMK, “PMK Name” || AA || SPA))

        R0-Key-Data = KDF-Hash-Length(XXKey, “FT-R0”, SSIDlength || SSID || MDID || R0KHlength || R0KH-ID || S0KH-ID)
        PMK-R0 = L(R0-Key-Data, 0, Q)
        PMK-R0Name-Salt = L(R0-Key-Data, Q, 128)
        Length = Q + 128
    """
    mpmk = msk[32:64]
    pmkid = hashlib.sha256(mpmk + b'PMK Name' + aa + spa).digest()[0:16]

    ssid_len = chr(len(ssid)).encode()
    r0khid_len = chr(len(r0khid)).encode()
    
    r0_key_data = sha256_kdf(mpmk, b'FT-R0', ssid_len + ssid + mdid + r0khid_len + r0khid + s0khid, 48)
    pmk_r0 = r0_key_data[0:32]
    pmk_r0_name_salt = r0_key_data[32:48]
    pmk_r0_name = hashlib.sha256(b'FT-R0N' + pmk_r0_name_salt).digest()[0:16]
    
    return pmkid, pmk_r0, pmk_r0_name


def get_pmkr1(pmk_r0, pmk_r0_name, r1khid, s1khid):
    """
    12.7.1.6.4 PMK-R1
        PMK-R1 = KDF-Hash-Length(PMK-R0, “FT-R1”, R1KH-ID || S1KH-ID)
        PMKR1Name = Truncate-128(Hash(“FT-R1N” || PMKR0Name || R1KH-ID || S1KH-ID))
    """
    pmk_r1 = sha256_kdf(pmk_r0, b'FT-R1', r1khid + s1khid, 32)
    pmk_r1_name = hashlib.sha256(b'FT-R1N' + pmk_r0_name + r1khid + s1khid).digest()[0:16]

    return pmk_r1, pmk_r1_name


def get_ptk(pmk_r1, pmk_r1_name, snonce, anonce, bssid, sta_addr):
    """
    12.7.1.6.5 PTK
        PTK = KDF-Hash-Length(PMK-R1, “FT-PTK”, SNonce || ANonce || BSSID || STA-ADDR)
        PTKName = Truncate-128(SHA-256(PMKR1Name || “FT-PTKN” || SNonce || ANonce || BSSID || STA-ADDR))
    """
    ptk = sha256_kdf(pmk_r1, b'FT-PTK', snonce + anonce + bssid + sta_addr, 48)
    ptk_name = hashlib.sha256(pmk_r1_name + b'FT-PTKN' + snonce + anonce + bssid + sta_addr).digest()[0:16]

    return ptk, ptk_name


def main():
    # PMK-R0
    pmkid, pmk_r0, pmk_r0_name = get_pmkr0(test_msk, test_ap_mac, test_client_mac, test_ssid, test_mdid, test_r0khid, test_client_mac)
    print(f"PMKID:      {pmkid.hex()}")
    print(f"PMK-R0:     {pmk_r0.hex()}")
    print(f"PMKR0Name:  {pmk_r0_name.hex()}")
    print()

    # PMK-R1
    pmk_r1, pmk_r1_name = get_pmkr1(pmk_r0, pmk_r0_name, test_r1khid, test_client_mac)
    print(f"PMK-R1:     {pmk_r1.hex()}")
    print(f"PMKR1Name:  {pmk_r1_name.hex()}")
    print()

    # PTK
    ptk, ptk_name = get_ptk(pmk_r1, pmk_r1_name, test_snonce, test_anonce, test_ap_mac, test_client_mac)
    kck = ptk[0:16]
    kek = ptk[16:32]
    tk = ptk[32:48]
    print(f"KCK:        {kck.hex()}")
    print(f"KEK:        {kek.hex()}")
    print(f"TK:         {tk.hex()}")
    print(f"PTKName:    {ptk_name.hex()}")


if __name__ == "__main__":
    main()