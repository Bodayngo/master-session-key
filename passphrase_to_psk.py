#!/usr/bin/env python3
"""

References:
    802.11-2020 Standard
        4.10.3.4 - Alternate operations with PSK
        Annex J.4 - Suggested pass-phrase-to-PSK mapping
    RFC 2898 - PKCS #5: Password-Based Cryptography Specification Version 2.0
        Section 5.2 - PBKDF2

"""

__author__ = "Evan Wilkerson"
__version__ = "0.1.0"

import argparse
import hashlib


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: An object containing the parsed command-line arguments.

    Raises:
        ValueError: If 'passphrase' is not an ASCII string.
        ValueError: If 'ssid' is not an ASCII string.

    """
    # Create an ArgumentParser object for parsing command-line arguments
    parser = argparse.ArgumentParser(
        description="Calculate the PSK for an SSID and passphrase"
    )

    # Add the 'passphrase' argument to the parser, specifying it as a required ASCII string
    parser.add_argument(
        "passphrase",
        type=str,
        help="The passphrase for the SSID, as an ASCII string",
    )
    # Add the 'ssid' argument to the parser, specifying it as a required ASCII string
    parser.add_argument(
        "ssid",
        type=str,
        help="The SSID name, as an ASCII string",
    )

    # Parse the command-line arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Check if the 'passphrase' argument is an ASCII string
    if not args.passphrase.isascii():
        raise ValueError("The passphrase must be an ASCII string.")
    # Check if the 'passphrase' argument is an ASCII string
    if not args.ssid.isascii():
        raise ValueError("The SSID must be an ASCII string.")

    # Return the parsed command-line arguments
    return args


def calculate_psk(passphrase: str, ssid: str) -> bytes:
    """
    Calculate the Pre-Shared Key (PSK) for a Wi-Fi network using the given passphrase and SSID.
    
    Args:
        passphrase (str): The passphrase for the Wi-Fi network. It must be between 8 and 63 characters long.
        ssid (str): The SSID (network name) of the Wi-Fi network.
        
    Returns:
        bytes: The calculated Pre-Shared Key (PSK) as bytes.

    Raises:
        ValueError: If the length of the passphrase is not between 8 and 63 characters.

    """
    
    # Check if the passphrase length is within the valid range (8 to 63 characters).
    if not 8 <= len(passphrase) <= 63:
        raise ValueError("Invalid passphrase length. It must be between 8 and 63 characters.")

    # Encode the passphrase and SSID to bytes for the PSK calculation.
    pass_phrase_bytes = passphrase.encode('ascii')
    ssid_bytes = ssid.encode('utf-8')

    # Calculate the PSK using PBKDF2-HMAC-SHA1 with 4096 iterations and a key length of 256 bits (32 bytes).
    psk = hashlib.pbkdf2_hmac('sha1', pass_phrase_bytes, ssid_bytes, 4096, 256 // 8)

    return psk


def main():
    """
    Main entry point of the script.

    """
    try:
        # Parse command line arguments
        arguments = parse_arguments()
        passphrase = arguments.passphrase
        ssid = arguments.ssid

        # Calculate the PSK using the provided input
        psk = calculate_psk(passphrase, ssid)
        
        # Print the PSK
        print()
        print(f"PSK/PMK: {psk.hex()}")
    
    except ValueError as e:
        # Handle ValueError exceptions
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(e)


if __name__ == "__main__":
    main()