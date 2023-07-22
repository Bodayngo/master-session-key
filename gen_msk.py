#!/usr/bin/env python3
"""
This script calculates the MSK by decrypting the  MPPE keys in a RADIUS Access-Accept using the RADIUS shared secret 
and the Request-Authenticator in the previous Access-Request.

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
    python3 get_msk.py <radius_shared_secret> <encrypted_ms_mppe_recv_key> <encrypted_ms_mppe_send_key> <request_authenticator>

        - radius_shared_secret:         The RADIUS shared secret configured on both the AP and RADIUS server, as an ASCII string
        - encrypted_ms_mppe_recv_key:   The MS-MPPE-Recv-Key value in the Access-Accept, as a hexidecimal string
        - encrypted_ms_mppe_send_key:   The MS-MPPE-Send-Key value in the Access-Accept, as a hexidecimal string
        - request_authenticator:        The Request-Authenticator value in the previous Access-Request, as a hexidecimal string

"""

__author__ = "Evan Wilkerson"
__version__ = "0.1.2"

import argparse
import re
import struct
from hashlib import md5


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: An object containing the parsed command-line arguments.

    Raises:
        ValueError: If 'radius_shared_secret' is not an ASCII string.
        ValueError: If 'encrypted_ms_mppe_recv_key' is not a hexadecimal string.
        ValueError: If 'encrypted_ms_mppe_send_key' is not a hexadecimal string.
        ValueError: If 'request_authenticator' is not a hexadecimal string.

    """
    # Create an ArgumentParser object for parsing command-line arguments
    parser = argparse.ArgumentParser(
        description="Calculate the master session key (MSK)."
    )

    # Add the 'radius_shared_secret' argument to the parser, specifying it as a required ASCII string
    parser.add_argument(
        "radius_shared_secret",
        type=str,
        help="The RADIUS shared secret, as an ASCII string",
    )
    # Add the 'encrypted_ms_mppe_recv_key' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument(
        "encrypted_ms_mppe_recv_key",
        type=str,
        help="The encrypted MS-MPPE-Recv-Key value in the Access-Accept, as a hexidecimal string",
    )
    # Add the 'encrypted_ms_mppe_send_key' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument(
        "encrypted_ms_mppe_send_key",
        type=str,
        help="The encrypted MS-MPPE-Send-Key value in the Access-Accept, as a hexidecimal string",
    )
    # Add the 'request_authenticator' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument(
        "request_authenticator",
        type=str,
        help="The Request-Authenticator value in the previous Access-Request packet, as a hexidecimal string",
    )

    # Parse the command-line arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Check if the 'radius_shared_secret' argument is an ASCII string
    if not args.radius_shared_secret.isascii():
        raise ValueError("The RADIUS shared secret value must be an ASCII string.")

    # Compile a regular expression pattern for matching hexadecimal strings
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    # Check if the 'encrypted_ms_mppe_recv_key' argument is a hexadecimal string
    if not hex_regex.match(args.encrypted_ms_mppe_recv_key):
        raise ValueError(
            "The encrypted MS-MPPE-Recv-Key value must be a hexadecimal string."
        )
    # Check if the 'encrypted_ms_mppe_send_key' argument is a hexadecimal string
    if not hex_regex.match(args.encrypted_ms_mppe_send_key):
        raise ValueError(
            "The encrypted MS-MPPE-Send-Key value must be a hexadecimal string."
        )
    # Check if the 'request_authenticator' argument is a hexadecimal string
    if not hex_regex.match(args.request_authenticator):
        raise ValueError(
            "The Request-Authenticator value must be a hexadecimal string."
        )

    # Return the parsed command-line arguments
    return args


def xor_bits(byte_str1: bytes, byte_str2: bytes, byte_order='big') -> bytes:
    """
    Perform a bitwise XOR operation on two byte strings.

    Args:
        byte_str1 (bytes): The first byte string.
        byte_str2 (bytes): The second byte string.
        byteorder (str, optional): The byte order for both input byte strings and the result.
                                   Defaults to 'big'.

    Returns:
        bytes: The result of the XOR operation as a byte string.

    """
    # Determine the length of the result byte string based on the longer input byte string.
    result_length = max(len(byte_str1), len(byte_str2))

    # Perform the XOR operation on the shared bytes.
    result_int = int.from_bytes(byte_str1, byteorder=byte_order) ^ int.from_bytes(byte_str2, byteorder=byte_order)

    # Convert the result integer back to a byte string using the appropriate length and byte order.
    result_bytes = result_int.to_bytes(result_length, byteorder=byte_order)

    return result_bytes


def decrypt_mppe_key(
    radius_shared_secret: bytes,
    encrypted_ms_mppe_key: bytes,
    request_authenticator: bytes,
) -> bytes:
    """
    Decrypts an MS-MPPE-Key using the provided RADIUS shared secret and Request-Authenticator.

    Args:
        radius_shared_secret (bytes): The RADIUS shared secret used in the decryption process.
        encrypted_ms_mppe_key (bytes): The encrypted MS-MPPE-Key.
        request_authenticator (bytes): The Request-Authenticator used in the decryption process.

    Returns:
        bytes: The decrypted MPPE key.

    Raises:
        ValueError: If the 'encrypted_data' length is invalid.
        ValueError: If the 'request_authenticator' length is invalid.
        ValueError: If the 'salt' is invalid.
        ValueError: If the 'decrypted_data' is invalid.

    """
    PAD = b"\x00"
    BLOCK_SIZE = 16
    MAX_ENCRYPTED_DATA_LENGTH = 256
    SALT_LENGTH = 2

    # Separate the salt and encrypted data from the input encrypted MS-MPPE-Key value
    salt, encrypted_data = (
        encrypted_ms_mppe_key[:SALT_LENGTH],
        encrypted_ms_mppe_key[SALT_LENGTH:],
    )

    # Validate the Request-Authenticator bytes
    if (
        # Check if the length of the Request-Authenticator is 16 bytes
        len(request_authenticator) != 16 or
        # Check if the length of the Request-Authenticator is a multiple of BLOCK_SIZE
        len(request_authenticator) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid Request-Authenticator")
    # Validate the salt bytes
    if (
        # Check if the length of the salt is equal to the expected salt length
        len(salt) != SALT_LENGTH or 
        # Check if the most significant bit (leftmost) is set
        not salt[0] & 0x80
    ):
        raise ValueError("Invalid salt in MS-MPPE-Key")
    # Validate the encrypted data bytes
    if (
        # Check if the length of the encrypted data is less than or equal to MAX_ENCRYPTED_DATA_LENGTH
        len(encrypted_data) > MAX_ENCRYPTED_DATA_LENGTH or
        # Check if the length of the encrypted data is a multiple of BLOCK_SIZE
        len(encrypted_data) % BLOCK_SIZE != 0
    ):
        raise ValueError("Invalid encrypted key data in MS-MPPE-Key")

    # Initialize an empty list to store intermediate decryption results
    decrypted_data_blocks = []

    # Construct the initial hash input
    hash_input = radius_shared_secret + request_authenticator + salt

    # Iterate over the encrypted data in BLOCK_SIZE-byte blocks
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        encrypted_block = encrypted_data[i : i + BLOCK_SIZE]
        # Compute the MD5 hash of the hash input
        hash_value = md5(hash_input).digest()
        # XOR the hash result with the current encrypted block to obtain the intermediate decrypted block
        decrypted_block = xor_bits(hash_value, encrypted_block)
        # Append the intermediate decrypted block to the list
        decrypted_data_blocks.append(decrypted_block)
        # Update the hash input by concatenating the secret and the current encrypted block
        hash_input = radius_shared_secret + encrypted_block

    # Join the intermediate decrypted blocks to form the decrypted data
    decrypted_data = b"".join(decrypted_data_blocks)

    # Extract the length of the plaintext key and the actual plaintext key from the decrypted data
    plaintext_key_length, padded_plaintext_key = (
        struct.unpack("!B", decrypted_data[:1])[0],
        decrypted_data[1:],
    )
    # Validate the decrypted data
    if (
        # Check if the plaintext key length greater than the padded plaintext key
        plaintext_key_length > len(padded_plaintext_key) or
        # Check if the length of the appended padding is less than BLOCK_SIZE
        len(padded_plaintext_key) - plaintext_key_length > BLOCK_SIZE - 1 or
        # Check if the appended padding is equal to PAD * the length of padding
        padded_plaintext_key[plaintext_key_length:] != PAD * (len(padded_plaintext_key) - plaintext_key_length)
    ):
        raise ValueError("Invalid decrypted data")

    # Remove the appended padding from the plaintext key
    plaintext_key = padded_plaintext_key[:plaintext_key_length]

    # Return the plaintext key
    return plaintext_key


def calculate_msk(
    radius_shared_secret: bytes,
    encrypted_ms_mppe_recv_key: bytes,
    encrypted_ms_mppe_send_key: bytes,
    request_authenticator: bytes,
) -> bytes:
    """
    Calculate the Master Session Key (MSK) by decrypting the MS-MPPE-Recv-Key and MS-MPPE-Send-Key
    using the provided RADIUS shared secret and Request-Authenticator.

    Args:
        radius_shared_secret (bytes): The RADIUS shared secret.
        encrypted_ms_mppe_recv_key (bytes): The MS-MPPE-Recv-Key value in the Access-Accept.
        encrypted_ms_mppe_send_key (bytes): The MS-MPPE-Send-Key value in the Access-Accept.
        request_authenticator (bytes): The Request-Authenticator value in the previous Access-Request packet.

    Returns:
        bytes: The calculated MSK.

    """
    # Decrypt the MS-MPPE-Keys using the RADIUS shared secret and Request-Authenticator
    decrypted_ms_mppe_recv_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_recv_key, request_authenticator
    )
    decrypted_ms_mppe_send_key = decrypt_mppe_key(
        radius_shared_secret, encrypted_ms_mppe_send_key, request_authenticator
    )

    # Concatenate the decrypted MS-MPPE-Keys to create the MSK
    master_session_key = (
        decrypted_ms_mppe_recv_key[:32] + decrypted_ms_mppe_send_key[:32]
    )

    # Return the MSK
    return master_session_key


def main():
    """
    Main entry point of the script

    """
    try:
        # Parse command-line arguments
        arguments = parse_arguments()

        # Convert the arguments from the command line to bytes
        radius_shared_secret = bytes(arguments.radius_shared_secret, "ascii")
        encrypted_ms_mppe_recv_key = bytes.fromhex(arguments.encrypted_ms_mppe_recv_key)
        encrypted_ms_mppe_send_key = bytes.fromhex(arguments.encrypted_ms_mppe_send_key)
        request_authenticator = bytes.fromhex(arguments.request_authenticator)

        # Calculate the MSK using the provided input
        msk = calculate_msk(
            radius_shared_secret,
            encrypted_ms_mppe_recv_key,
            encrypted_ms_mppe_send_key,
            request_authenticator,
        )

        # Print the MSK in hexidecimal format
        print()
        print(f"Master Session Key (MSK):  {msk.hex()}")

    except ValueError as e:
        # Handle ValueError exceptions
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
