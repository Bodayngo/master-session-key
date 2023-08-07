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
            The RADIUS shared secret, as an ASCII string.
        - mppe_recv_key:
            The MS-MPPE-Recv-Key value in the Access-Accept,
            as a hexidecimal string.
        - mppe_send_key:
            The MS-MPPE-Send-Key value in the Access-Accept,
            as a hexidecimal string.
        - authenticator:
            The Request-Authenticator value in the previous Access-Request,
            as a hexidecimal string.

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
            - If 'secret' is not an ASCII string.
            - If 'mppe_recv_key' is not a hexadecimal string.
            - If 'mppe_send_key' is not a hexadecimal string.
            - If 'authenticator' is not a hexadecimal string.

    """
    # Create an ArgumentParser object for parsing command-line arguments.
    parser = argparse.ArgumentParser(
        description="Calculate the master session key (MSK)."
    )

    # Add the 'secret' argument to the parser.
    parser.add_argument(
        "secret",
        type=str,
        help="The RADIUS shared secret, as an ASCII string.",
    )
    # Add the 'mppe_recv_key' argument to the parser.
    parser.add_argument(
        "mppe_recv_key",
        type=str,
        help="""\
            The encrypted MS-MPPE-Recv-Key value in the Access-Accept
            packet, as a hexidecimal string.
            """,
    )
    # Add the 'mppe_send_key' argument to the parser.
    parser.add_argument(
        "mppe_send_key",
        type=str,
        help="""\
            The encrypted MS-MPPE-Send-Key value in the Access-Accept
            packet, as a hexidecimal string.
            """,
    )
    # Add the 'authenticator' argument to the parser.
    parser.add_argument(
        "authenticator",
        type=str,
        help="""\
            The Request-Authenticator value in the previous Access-Request
            packet, as a hexidecimal string.
            """,
    )

    # Parse the command-line arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Check if the 'secret' argument is an ASCII string
    if not args.secret.isascii():
        raise ValueError("The RADIUS shared secret must be an ASCII string.")

    # Compile a regular expression pattern for matching hexadecimal strings.
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    # Check if 'mppe_recv_key' argument is a hexadecimal string.
    if not hex_regex.match(args.mppe_recv_key):
        raise ValueError(
            "The encrypted MS-MPPE-Recv-Key must be a hexadecimal string."
        )
    # Check if 'mppe_send_key' argument is a hexadecimal string.
    if not hex_regex.match(args.mppe_send_key):
        raise ValueError(
            "The encrypted MS-MPPE-Send-Key must be a hexadecimal string."
        )
    # Check if 'authenticator' argument is a hexadecimal string.
    if not hex_regex.match(args.authenticator):
        raise ValueError(
            "The Request-Authenticator must be a hexadecimal string."
        )

    # Return the parsed command-line arguments
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
            - The result of the XOR operation.

    """
    # Determine the length of the result byte string based on the longer
    # input byte string.
    result_length = max(len(byte_str1), len(byte_str2))

    # Convert bytes to integer representation.
    int1 = int.from_bytes(byte_str1, byteorder=byte_order)
    int2 = int.from_bytes(byte_str2, byteorder=byte_order)

    # Perform the XOR operation on the provided bytes.
    result_int = int1 ^ int2

    # Convert the result integer back to a byte string using the appropriate
    # length and byte order.
    result_bytes = result_int.to_bytes(result_length, byteorder=byte_order)

    # Return the XOR result bytes.
    return result_bytes


def decrypt_mppe_key(
    radius_shared_secret: bytes,
    encrypted_ms_mppe_key: bytes,
    request_authenticator: bytes,
) -> bytes:
    """Decrypt an MS-MPPE-Key.

    Decrypts an MS-MPPE-Key using the provided RADIUS shared
    secret and Request-Authenticator.

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

    # Separate the salt and encrypted data from the input encrypted key.
    salt, encrypted_data = (
        encrypted_ms_mppe_key[:SALT_LENGTH],
        encrypted_ms_mppe_key[SALT_LENGTH:],
    )

    # Validate the Request-Authenticator bytes.
    if (
        # Check if length is 16 bytes
        len(request_authenticator) != 16
        or
        # Check if length is a multiple of BLOCK_SIZE.
        len(request_authenticator) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid Request-Authenticator")
    # Validate the salt bytes.
    if (
        # Check if length is equal to the expected salt length.
        len(salt) != SALT_LENGTH
        or
        # Check if most significant bit (leftmost) is set.
        not salt[0] & 0x80
    ):
        raise ValueError("Invalid salt in MS-MPPE-Key")
    # Validate the encrypted data bytes.
    if (
        # Check if length is less than or equal to MAX_ENCRYPTED_DATA_LENGTH.
        len(encrypted_data) > MAX_ENCRYPTED_DATA_LENGTH
        or
        # Check if length is a multiple of BLOCK_SIZE.
        len(encrypted_data) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid encrypted key data in MS-MPPE-Key")

    # Initialize an empty list to store intermediate decryption results.
    decrypted_data_blocks = []

    # Construct the initial hash input.
    hash_input = radius_shared_secret + request_authenticator + salt

    # Iterate over the encrypted data in BLOCK_SIZE-byte blocks.
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        encrypted_block = encrypted_data[i: i + BLOCK_SIZE]
        # Compute the MD5 hash of the hash input.
        hash_value = md5(hash_input).digest()
        # XOR the hash result with the current encrypted block to obtain
        # the intermediate decrypted block.
        decrypted_block = xor_bits(hash_value, encrypted_block)
        # Append the intermediate decrypted block to the list.
        decrypted_data_blocks.append(decrypted_block)
        # Update the hash input by concatenating the secret and the current
        # encrypted block.
        hash_input = radius_shared_secret + encrypted_block

    # Join the intermediate decrypted blocks to form the decrypted data.
    decrypted_data = b"".join(decrypted_data_blocks)

    # Extract the length of the plaintext key and the actual plaintext key
    # from the decrypted data.
    plaintext_key_length, padded_plaintext_key = (
        struct.unpack("!B", decrypted_data[:1])[0],
        decrypted_data[1:],
    )
    # Validate the decrypted data.
    if (
        # Check if plaintext key length value is greater than the length of
        # the padded plaintext key.
        plaintext_key_length > len(padded_plaintext_key)
        or
        # Check if length of the appended padding is less than BLOCK_SIZE.
        len(padded_plaintext_key) - plaintext_key_length > BLOCK_SIZE - 1
        or
        # Check if appended padding is equal to PAD * the length of padding.
        padded_plaintext_key[plaintext_key_length:]
        != PAD * (len(padded_plaintext_key) - plaintext_key_length)
    ):
        raise ValueError("Invalid decrypted data")

    # Remove the appended padding from the plaintext key.
    plaintext_key = padded_plaintext_key[:plaintext_key_length]

    # Return the plaintext key.
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
    Request-Authenticator. Once decrypted, the first 32 bytes of each MPPE key
    are concatentated to form the MSK.

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
    # Decrypt the MS-MPPE-Recv-Key
    decrypted_ms_mppe_recv_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_recv_key, request_authenticator
    )
    # Decrypt the MS-MPPE-Send-Key
    decrypted_ms_mppe_send_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_send_key, request_authenticator
    )

    # Concatenate the decrypted MS-MPPE-Keys to create the MSK
    master_session_key_bytes = (
        decrypted_ms_mppe_recv_key[:32] + decrypted_ms_mppe_send_key[:32]
    )
    # Convert the MSK from bytes to hexadecimal
    master_session_key_hex = master_session_key_bytes.hex()

    # Return the MSK
    return master_session_key_hex


def main():
    """Entry point."""
    try:
        # Parse command line arguments.
        arguments = parse_arguments()

        # Convert the arguments from the command line to bytes
        radius_shared_secret = bytes(arguments.secret, "ascii")
        encrypted_ms_mppe_recv_key = bytes.fromhex(
            arguments.mppe_recv_key
        )
        encrypted_ms_mppe_send_key = bytes.fromhex(
            arguments.mppe_send_key
        )
        request_authenticator = bytes.fromhex(
            arguments.authenticator
        )

        # Calculate MSK using the provided input
        msk = calculate_msk(
            radius_shared_secret,
            encrypted_ms_mppe_recv_key,
            encrypted_ms_mppe_send_key,
            request_authenticator,
        )

        # Print the MSK
        print(f"\nMaster Session Key (MSK):  {msk}")

    except ValueError as e:
        # Handle ValueError exceptions
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
