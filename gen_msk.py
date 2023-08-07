#!/usr/bin/env python3
"""Calculate MSK.

This script calculates the MSK by decrypting the  MPPE keys in a RADIUS
Access-Accept using the RADIUS shared secret and the Request-Authenticator
in the previous Access-Request.

References:
    802.11-2020 Standard
        Sub-clause 12.7.1.3 - Pairwise key hierarchy
        Sub-clause 12.7.1.6 - FT key hierarchy
    RFC 3748 - EAP
        Section 7.10 - Key Derivation
    RFC 5216 - EAP-TLS Authentication Protocol
        Section 2.3 - Key Hierarchy
    RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
        Section 3 - Packet Format
    RFC 2548 - Microsoft Vendor-specific RADIUS Attributes
        Section 2.4.2 - MS-MPPE-Send-Key
        Section 2.4.3 - MS-MPPE-Recv-Key

Usage:
    python3 get_msk.py <secret> <mppe_recv_key> <mppe_send_key> <authenticator>

        - secret:
            The RADIUS shared secret, as an ASCII string
        - mppe_recv_key:
            The MS-MPPE-Recv-Key value in the Access-Accept,
            as a hexidecimal string
        - mppe_send_key:
            The MS-MPPE-Send-Key value in the Access-Accept,
            as a hexidecimal string
        - authenticator:
            The Request-Authenticator value in the previous Access-Request,
            as a hexidecimal string

"""

__author__ = "Evan Wilkerson"
__version__ = "0.1.2"

import argparse
import re
import struct
from hashlib import md5


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace:
            - An object containing the parsed command-line arguments.

    Raises:
        ValueError:
            - If 'radius_shared_secret' is not an ASCII string.
            - If 'encrypted_ms_mppe_recv_key' is not a hexadecimal string.
            - If 'encrypted_ms_mppe_send_key' is not a hexadecimal string.
            - If 'request_authenticator' is not a hexadecimal string.

    """
    parser = argparse.ArgumentParser(
        description="Calculate the master session key (MSK)."
    )

    parser.add_argument(
        "radius_shared_secret",
        type=str,
        help="The RADIUS shared secret, as an ASCII string",
    )
    parser.add_argument(
        "encrypted_ms_mppe_recv_key",
        type=str,
        help="""\
            The encrypted MS-MPPE-Recv-Key value in the Access-Accept
            packet, as a hexidecimal string
            """,
    )
    parser.add_argument(
        "encrypted_ms_mppe_send_key",
        type=str,
        help="""\
            The encrypted MS-MPPE-Send-Key value in the Access-Accept
            packet, as a hexidecimal string
            """,
    )
    parser.add_argument(
        "request_authenticator",
        type=str,
        help="""\
            The Request-Authenticator value in the previous Access-Request
            packet, as a hexidecimal string
            """,
    )

    args = parser.parse_args()

    if not args.radius_shared_secret.isascii():
        raise ValueError("The RADIUS shared secret must be an ASCII string.")

    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    if not hex_regex.match(args.encrypted_ms_mppe_recv_key):
        raise ValueError(
            "The encrypted MS-MPPE-Recv-Key must be a hexadecimal string."
        )
    if not hex_regex.match(args.encrypted_ms_mppe_send_key):
        raise ValueError(
            "The encrypted MS-MPPE-Send-Key must be a hexadecimal string."
        )
    if not hex_regex.match(args.request_authenticator):
        raise ValueError(
            "The Request-Authenticator must be a hexadecimal string."
        )

    return args


def xor_bits(byte_str1: bytes, byte_str2: bytes, byte_order="big") -> bytes:
    """Perform a bitwise XOR operation on two byte strings.

    Args:
        byte_str1 (bytes):
            - The first byte string.
        byte_str2 (bytes):
            - The second byte string.
        byteorder (str, optional):
            - The byte order for both input byte strings
              and the result. Defaults to 'big'.

    Returns:
        bytes:
            - The result of the XOR operation as a byte string.

    """
    result_length = max(len(byte_str1), len(byte_str2))

    int1 = int.from_bytes(byte_str1, byteorder=byte_order)
    int2 = int.from_bytes(byte_str2, byteorder=byte_order)

    result_int = int1 ^ int2

    result_bytes = result_int.to_bytes(result_length, byteorder=byte_order)

    return result_bytes


def decrypt_mppe_key(
    radius_shared_secret: bytes,
    encrypted_ms_mppe_key: bytes,
    request_authenticator: bytes,
) -> bytes:
    """Decrypt an MS-MPPE-Key.

    Decrypts an MS-MPPE-Key using the provided RADIUS shared
    secret and Request-Authenticator.

    The decryption process involves several steps:
        - Separating the salt and cipher from the input cipher bytes.
        - Checking the validity of the encrypted data length, request
          authenticator length, and salt.
        - Initializing an empty list to store intermediate decryption results.
        - Constructing the initial hash input by concatenating the secret,
          authenticator, and salt.
        - Iterating over the cipher in 16-byte blocks and performing the
          following steps for each block:
            - Computing the MD5 hash of the hash input.
            - XORing the hash result with the current block to obtain the
              intermediate decrypted block.
            - Appending the intermediate decrypted block to the list.
            - Updating the hash input by concatenating the secret and the
              current block.
        - Joining the intermediate decrypted blocks to form the
          decrypted message.
        - Extracting the length of the clear data and the actual clear
          data from the decrypted message.
        - Performing additional checks on the length and padding of
          the clear data.
        - Returning the clear data up to the specified length.

    Args:
        radius_shared_secret (bytes):
            - The RADIUS shared secret used in the decryption process.
        encrypted_ms_mppe_key (bytes):
            - The encrypted MS-MPPE-Key.
        request_authenticator (bytes):
            - The Request-Authenticator used in the decryption process.

    Returns:
        bytes:
            - The decrypted MPPE key.

    Raises:
        ValueError:
            - If the 'encrypted_data' length is invalid.
            - If the 'request_authenticator' length is invalid.
            - If the 'salt' is invalid.
            - If the 'decrypted_data' is invalid.

    """
    PAD = b"\x00"
    BLOCK_SIZE = 16
    MAX_ENCRYPTED_DATA_LENGTH = 256
    SALT_LENGTH = 2

    salt, encrypted_data = (
        encrypted_ms_mppe_key[:SALT_LENGTH],
        encrypted_ms_mppe_key[SALT_LENGTH:],
    )

    if (
        len(request_authenticator) != 16
        or
        len(request_authenticator) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid Request-Authenticator")
    if (
        len(salt) != SALT_LENGTH
        or
        not salt[0] & 0x80
    ):
        raise ValueError("Invalid salt in MS-MPPE-Key")
    if (
        len(encrypted_data) > MAX_ENCRYPTED_DATA_LENGTH
        or
        len(encrypted_data) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid encrypted key data in MS-MPPE-Key")

    decrypted_data_blocks = []

    hash_input = radius_shared_secret + request_authenticator + salt

    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        encrypted_block = encrypted_data[i: i + BLOCK_SIZE]
        hash_value = md5(hash_input).digest()
        decrypted_block = xor_bits(hash_value, encrypted_block)
        decrypted_data_blocks.append(decrypted_block)
        hash_input = radius_shared_secret + encrypted_block

    decrypted_data = b"".join(decrypted_data_blocks)

    plaintext_key_length, padded_plaintext_key = (
        struct.unpack("!B", decrypted_data[:1])[0],
        decrypted_data[1:],
    )
    if (
        plaintext_key_length > len(padded_plaintext_key)
        or
        len(padded_plaintext_key) - plaintext_key_length > BLOCK_SIZE - 1
        or
        padded_plaintext_key[plaintext_key_length:]
        != PAD * (len(padded_plaintext_key) - plaintext_key_length)
    ):
        raise ValueError("Invalid decrypted data")

    plaintext_key = padded_plaintext_key[:plaintext_key_length]

    return plaintext_key


def calculate_msk(
    radius_shared_secret: bytes,
    encrypted_ms_mppe_recv_key: bytes,
    encrypted_ms_mppe_send_key: bytes,
    request_authenticator: bytes,
) -> bytes:
    """Caclulate MSK.

    Calculate the Master Session Key (MSK) by decrypting the MS-MPPE-Recv-Key
    and MS-MPPE-Send-Key using the provided RADIUS shared secret and
    Request-Authenticator.

    Args:
        radius_shared_secret (bytes):
            - The RADIUS shared secret.
        encrypted_ms_mppe_recv_key (bytes):
            - The MS-MPPE-Recv-Key value in the Access-Accept.
        encrypted_ms_mppe_send_key (bytes):
            - The MS-MPPE-Send-Key value in the Access-Accept.
        request_authenticator (bytes):
            - The Request-Authenticator value in the previous
              Access-Request packet.

    Returns:
        str:
            - The calculated MSK, in hexadecimal format.

    """
    decrypted_ms_mppe_recv_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_recv_key, request_authenticator
    )
    decrypted_ms_mppe_send_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_send_key, request_authenticator
    )

    master_session_key_bytes = (
        decrypted_ms_mppe_recv_key[:32] + decrypted_ms_mppe_send_key[:32]
    )
    master_session_key_hex = master_session_key_bytes.hex()

    return master_session_key_hex


def main():
    """Entry point."""
    try:
        arguments = parse_arguments()

        radius_shared_secret = bytes(arguments.radius_shared_secret, "ascii")
        encrypted_ms_mppe_recv_key = bytes.fromhex(
            arguments.encrypted_ms_mppe_recv_key
            )
        encrypted_ms_mppe_send_key = bytes.fromhex(
            arguments.encrypted_ms_mppe_send_key
            )
        request_authenticator = bytes.fromhex(
            arguments.request_authenticator
            )

        msk = calculate_msk(
            radius_shared_secret,
            encrypted_ms_mppe_recv_key,
            encrypted_ms_mppe_send_key,
            request_authenticator,
        )

        print(f"\nMaster Session Key (MSK):  {msk}")

    except ValueError as e:
        print(e)

    except Exception as e:
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
