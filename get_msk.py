#!/usr/bin/env python3
"""
This script derives the MSK by decrypting the  MPPE keys in a RADIUS Access-Accept using the RADIUS shared secret 
and the Request-Authenticator in the previous Access-Request.

References:
    802.11-2020 Standard
        Sub-clause 12.7.1.3 - Pairwise key hierarchy
        Sub-clause 12.7.1.6 - FT key hierarchy
    RFC 3748 - EAP (https://datatracker.ietf.org/doc/html/rfc3748)
        Section 7.10 - Key Derivation
    RFC 5216 - EAP-TLS Authentication Protocol (https://datatracker.ietf.org/doc/html/rfc5216)
        Section 2.3 - Key Hierarchy
    RFC 2548 - Microsoft Vendor-specific RADIUS Attributes (https://datatracker.ietf.org/doc/html/rfc2548)
        Section 2.4.2 - MS-MPPE-Send-Key
        Section 2.4.3 - MS-MPPE-Recv-Key

Usage:
    python3 msk.py <secret> <authenticator> <mppe_recv_key> <mppe_send_key>
        - secret:             The RADIUS shared secret configured on both the AP and RADIUS server, as an ASCII string
        - ms_mppe_recv_key:   The MS-MPPE-Recv-Key value in the Access-Accept, as a hexidecimal string
        - ms_mppe_send_key:   The MS-MPPE-Send-Key value in the Access-Accept, as a hexidecimal string
        - authenticator:      The Request-Authenticator value in the previous Access-Request, as a hexidecimal string

"""

import argparse, re, struct
from hashlib import md5


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        args (argparse.Namespace): An object containing the parsed command-line arguments.

    Raises:
        ValueError: If 'secret' is not an ASCII string.
        ValueError: If 'authenticator', 'ms_mppe_recv_key', or 'ms_mppe_send_key' is not a hexadecimal string.
    """
    # Create an ArgumentParser object for parsing command-line arguments
    parser = argparse.ArgumentParser(description="Decrypt the MS-MPPE-Send-Key and MS-MPPE-Recv-Key attribute of RADIUS messages to derive the MSK.")

    # Add the 'secret' argument to the parser, specifying it as a required ASCII string
    parser.add_argument("secret", type=str, help="The RADIUS shared secret, as an ASCII string")
    # Add the 'ms_mppe_recv_key' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument("ms_mppe_recv_key", type=str, help="MS-MPPE-Recv-Key value in the Access-Accept, as a hexidecimal string",)
    # Add the 'ms_mppe_send_key' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument("ms_mppe_send_key", type=str, help="MS-MPPE-Send-Key value in the Access-Accept, as a hexidecimal string",)
    # Add the 'authenticator' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument("authenticator", type=str, help="The Request-Authenticator value in the previous Access-Request packet, as a hexidecimal string",)

    # Parse the command-line arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Check if the 'secret' argument is an ASCII string
    if not args.secret.isascii():
        raise ValueError("The RADIUS shared secret must be an ASCII string.")
    
    # Compile a regular expression pattern for matching hexadecimal strings
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    # Check if the 'ms_mppe_recv_key' argument is a hexadecimal string
    if not hex_regex.match(args.ms_mppe_recv_key):
        raise ValueError("The MS-MPPE-Recv-Key must be a hexadecimal string.")
    # Check if the 'ms_mppe_send_key' argument is a hexadecimal string
    if not hex_regex.match(args.ms_mppe_send_key):
        raise ValueError("The MS-MPPE-Send-Key must be a hexadecimal string.")
    # Check if the 'authenticator' argument is a hexadecimal string
    if not hex_regex.match(args.authenticator):
        raise ValueError("The Request-Authenticator must be a hexadecimal string.")
    
    # Return the parsed command-line arguments
    return args


def decrypt_mppe_key(ciphertext: bytes, secret: bytes, authenticator: bytes, pad: bytes = b"\x00") -> bytes:
    """
    Decrypts an MPPE key using the provided ciphertext, secret, authenticator, and padding.

    Args:
        ciphertext (bytes): The encrypted MPPE key.
        secret (bytes): The shared secret used in the decryption process.
        authenticator (bytes): The authenticator used in the decryption process.
        pad (bytes, optional): The padding character used in the decryption process (default is b"\x00").

    Returns:
        plaintext_key (bytes): The decrypted MPPE key.

    Raises:
        ValueError: If the 'encrypted_data' length is invalid.
        ValueError: If the 'authenticator' length is invalid.
        ValueError: If the 'salt' is invalid.
        ValueError: If the 'plaintext_key' is invalid.
    """
    BLOCK_SIZE = 16
    MAX_ENCRYPTED_DATA_LENGTH = 256
    SALT_LENGTH = 2

    # Separate the salt and encrypted data from the input ciphertext bytes
    salt, encrypted_data = ciphertext[:SALT_LENGTH], ciphertext[SALT_LENGTH:]

    # Check the length of the encrypted data to ensure it is a multiple of BLOCK_SIZE
    if len(encrypted_data) % BLOCK_SIZE != 0 or len(encrypted_data) > MAX_ENCRYPTED_DATA_LENGTH:
        raise ValueError("Invalid encrypted data length")

    # Check the length of the authenticator to ensure it is a multiple of BLOCK_SIZE
    if len(authenticator) % BLOCK_SIZE != 0:
        raise ValueError("Invalid request authenticator length")

    # Check the length of the salt and if the most significant bit (leftmost) is set (0x80)
    if len(salt) != SALT_LENGTH or not salt[0] & 0x80:
        raise ValueError("Invalid salt")

    # Initialize an empty list to store intermediate decryption results
    decrypted_data_blocks = []

    # Construct the initial hash input by concatenating the secret, authenticator, and salt
    hash_input = secret + authenticator + salt

    # Iterate over the encrypted data in BLOCK_SIZE-byte blocks
    for i in range(0, len(encrypted_data), BLOCK_SIZE):
        encrypted_block = encrypted_data[i : i + BLOCK_SIZE]
        # Compute the MD5 hash of the hash input
        hash_value = int(md5(hash_input).hexdigest(), 16)
        # XOR the hash result with the current encrypted block to obtain the intermediate decrypted block
        decrypted_block = bytes.fromhex("%032x" % (hash_value ^ int.from_bytes(encrypted_block, "big")))
        # Append the intermediate decrypted block to the list
        decrypted_data_blocks.append(decrypted_block)
        # Update the hash input by concatenating the secret and the current encrypted block
        hash_input = secret + encrypted_block

    # Join the intermediate decrypted blocks to form the decrypted data
    decrypted_data = b"".join(decrypted_data_blocks)

    # Extract the length of the plaintext key and the actual plaintext key from the decrypted data
    length, plaintext_key = struct.unpack("!B", decrypted_data[:1])[0], decrypted_data[1:]

    # Check if the length is valid and the padding is correct
    if (
        (length > len(plaintext_key)) or 
        (len(plaintext_key) - length > BLOCK_SIZE - 1) or 
        (plaintext_key[length:] != pad * (len(plaintext_key) - length))
    ):
        raise ValueError("Invalid decrypted data")

    # Return the plaintext key up to the specified length to remove appended padding
    return plaintext_key[:length]


def calculate_msk(secret: bytes, authenticator: bytes, ms_mppe_recv_key: bytes, ms_mppe_send_key: bytes) -> bytes:
    """
    Calculate the Master Session Key (MSK) by decrypting the MS-MPPE-Recv-Key and MS-MPPE-Send-Key
    using the provided secret and authenticator.

    Args:
        secret (bytes): The RADIUS shared secret.
        authenticator (bytes): The Request-Authenticator value in the previous Access-Request packet.
        ms_mppe_recv_key (bytes): The MS-MPPE-Recv-Key value in the Access-Accept.
        ms_mppe_send_key (bytes): The MS-MPPE-Send-Key value in the Access-Accept.

    Returns:
        master_session_key (bytes): The calculated Master Session Key (MSK).
    """
    # Decrypt the 'ms_mppe_recv_key' and 'ms_mppe_send_key' with the 'secret' and 'authenticator'
    decrypted_ms_mppe_recv_key = decrypt_mppe_key(ms_mppe_recv_key, secret, authenticator)
    decrypted_ms_mppe_send_key = decrypt_mppe_key(ms_mppe_send_key, secret, authenticator)

    # Concatenate the decrypted MS-MPPE-Recv-Key + MS-MPPE-Send-Key to get the MSK
    master_session_key = decrypted_ms_mppe_recv_key[:32] + decrypted_ms_mppe_send_key[:32]

    # Return the master session key (MSK)
    return master_session_key


def main():
    """
    Main function for calculating the MSK.
    """
    try:
        # Parse command-line arguments
        arguments = parse_arguments()

        # Convert the 'secret' argument from the command line to bytes using ASCII encoding
        secret = bytes(arguments.secret, 'ascii')

        #Convert the 'authenticator', 'ms_mppe_recv_key', and 'ms_mppe_send_key' arguments from the command line to bytes using hexadecimal decoding
        ms_mppe_recv_key = bytes.fromhex(arguments.ms_mppe_recv_key)
        ms_mppe_send_key = bytes.fromhex(arguments.ms_mppe_send_key)
        authenticator = bytes.fromhex(arguments.authenticator)

        # Calculate the MSK using the provided input
        msk = calculate_msk(secret, authenticator, ms_mppe_recv_key, ms_mppe_send_key)

        # Print the MSK in hexidecimal format
        print(f"Master Session Key (MSK):  {msk.hex()}")

    except ValueError as e:
        # Handle specific ValueError (e.g., if the arguments are not in the expected format)
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
