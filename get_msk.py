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

from binascii import unhexlify, hexlify
from hashlib import md5
import argparse, re


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Description:
        This function parses the command-line arguments necessary for decrypting the MS-MPPE-Send-Key and MS-MPPE-Recv-Key attributes
        of RADIUS messages to derive the MSK (Master Session Key). The function expects four arguments: 'secret', 'authenticator',
        'mppe_recv_key', and 'mppe_send_key'; all of which are required.

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

    Description:
        The function takes an encrypted MPPE key, a shared secret, an authenticator, and an optional padding character
        as input. It performs the decryption process and returns the decrypted MPPE key.

        The decryption process involves several steps:
            - Separating the salt and encrypted data from the input ciphertext bytes.
            - Checking the validity of the encrypted data length, request authenticator length, and salt.
            - Initializing an empty list to store intermediate decryption results.
            - Constructing the initial hash input by concatenating the secret, authenticator, and salt.
            - Iterating over the encrypted data in 16-byte blocks and performing the following steps for each encrypted block:
                - Computing the MD5 hash of the hash input.
                - XORing the hash result with the current encrypted block to obtain the intermediate decrypted block.
                - Appending the intermediate decrypted block to the list.
                - Updating the hash input by concatenating the secret and the current encrypted block.
            - Joining the intermediate decrypted blocks to form the decrypted data.
            - Extracting the length of the plaintext key and the actual plaintext key from the decrypted data.
            - Performing additional checks on the length and padding of the plaintext key.
            - Returning the plaintext key up to the specified length to remove appended padding.

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
    # Separate the salt and encrypted data from the input ciphertext bytes
    salt, encrypted_data = ciphertext[0:2], ciphertext[2:]

    # Check the length of the encrypted data to ensure it is a multiple of 16 and not exceeding 256 bytes
    if len(encrypted_data) % 16 or len(encrypted_data) > 256:
        raise ValueError("Invalid encrypted data length")
    # Check the length of the authenticator to ensure it is a multiple of 16
    if len(authenticator) % 16:
        raise ValueError("Invalid request authenticator length")
    # Check the length of the salt and if the most significant bit (lefmost) is set (0x80)
    if len(salt) != 2 or not salt[0] & 0x80:
        raise ValueError("Invalid salt")
    
    # Initialize an empty list to store intermediate decryption results.
    decrypted_data_blocks = []
    # Construct the initial hash input by concatenating the secret, authenticator, and salt
    hash_input = secret + authenticator + salt

    # Iterate over the encrypted data in 16-byte blocks
    for i in range(0, len(encrypted_data), 16):
        encrypted_block = encrypted_data[i : i + 16]
        # Compute the MD5 hash of the hash input
        hash = int(hexlify(md5(hash_input).digest()), 16)
        # XOR the hash result with the current encrypted block to obtain the intermediate decrypted block
        decrypted_block = unhexlify("%032x" % (hash ^ int(hexlify(encrypted_block), 16)))
        # Append the intermediate decrypted block to the list
        decrypted_data_blocks.append(decrypted_block)
        # Update the hash input by concatenating the secret and the current encrypted block
        hash_input = secret + encrypted_block
    
    # Join the intermediate decrypted blocks to form the decrypted data
    decrypted_data = b"".join(decrypted_data_blocks)

    # Extract the length of the plaintext key and the actual plaintext key from the decrypted data
    length, plaintext_key = decrypted_data[0], decrypted_data[1:]
    # Check if the length is valid and the padding is correct
    if (length > len(plaintext_key)) or (len(plaintext_key) - length > 15) or (plaintext_key[length:] != pad * (len(plaintext_key) - length)):
        raise ValueError("Invalid plaintext key")
    
    # Return the plaintext key up to the specified length to remove appended padding
    return plaintext_key[:length]


def main():
    """
    Main function for decrypting MS-MPPE-Send-Key and MS-MPPE-Recv-Key attributes of RADIUS messages.

    Description:
        This function serves as the entry point for decrypting the MS-MPPE-Send-Key and MS-MPPE-Recv-Key attributes of RADIUS messages.

        It follows the steps below to perform the decryption and derive the MSK:
            - Parse command-line arguments using the `parse_arguments()` function.
            - Convert the 'secret' argument from the command line to bytes using ASCII encoding.
            - Convert the 'authenticator', 'ms_mppe_recv_key', and 'ms_mppe_send_key' arguments from the command line to bytes using hexadecimal decoding.
            - Decrypt the 'ms_mppe_recv_key' and 'ms_mppe_send_key' using the 'decrypt_mppe_key()' function with the 'secret' and 'authenticator'.
            - Decode the first 32 bytes of 'decrypted_ms_mppe_recv_key' and 'decrypted_ms_mppe_send_key' as hexadecimal strings
            - Print the MS-MPPE-Send-Key, MS-MPPE-Send-Key, and the master session key (MSK).
                - Concatenate the MS-MPPE-Recv-Key + MS-MPPE-Send-Key to get the MSK

    """
    try:
        # Parse command-line arguments
        arguments = parse_arguments()

        # Convert the 'secret' argument from the command line to bytes using ASCII encoding
        secret = bytes(arguments.secret, 'ascii')

        #Convert the 'authenticator', 'ms_mppe_recv_key', and 'ms_mppe_send_key' arguments from the command line to bytes using hexadecimal decoding
        ms_mppe_recv_key = unhexlify(arguments.ms_mppe_recv_key)
        ms_mppe_send_key = unhexlify(arguments.ms_mppe_send_key)
        authenticator = unhexlify(arguments.authenticator)

        # Decrypt the 'ms_mppe_recv_key' and 'ms_mppe_send_key' with the 'secret' and 'authenticator'
        decrypted_ms_mppe_recv_key = decrypt_mppe_key(ms_mppe_recv_key, secret, authenticator,)
        decrypted_ms_mppe_send_key = decrypt_mppe_key(ms_mppe_send_key, secret, authenticator,)

        # Decode the first 32 bytes of 'decrypted_ms_mppe_recv_key' and 'decrypted_ms_mppe_send_key' as hexadecimal strings
        decoded_ms_mppe_recv_key = hexlify(decrypted_ms_mppe_recv_key[:32]).encode()
        decoded_ms_mppe_send_key = hexlify(decrypted_ms_mppe_send_key[:32]).encode()

        # Print the decrypted MS-MPPE-Recv-Key, decrypted MS-MPPE-Send-Key, and the master session key (MSK)
        print(f"MS-MPPE-Recv-Key:    {decoded_ms_mppe_recv_key}")
        print(f"MS-MPPE-Send-Key:    {decoded_ms_mppe_send_key}")
        print(f"Master Session Key:  {decoded_ms_mppe_recv_key + decoded_ms_mppe_send_key}")

    except ValueError as e:
        # Handle specific ValueError (e.g., if the arguments are not in the expected format)
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
