#!/usr/bin/env python3
"""
This script calculates the PMKID using the pairwise master key (PMK), authenticator address (AA) 
and the supplicant address (SPA). Different PMKIDs are calculated using SHA-1, SHA-256, and SHA-384.

References:
    802.11-2020 Standard
        Sub-clause 12.7.1.3 - Pairwise key hierarchy
        Sub-clause 12.7.1.6.3 - PMK-R0

SHA methods and associated AKM suite types:

    SHA-1
        00-0F-AC:1 - Authentication negotiated over IEEE Std 802.1X
        00-0F-AC:2 - PSK

    SHA-256
        00-0F-AC:3 - FT authentication negotiated over IEEE Std 802.1X (PMKID for cached MPMK)
        00-0F-AC:4 - FT authentication using PSK (PMKID for cached MPMK)
        00-0F-AC:5 - Authentication negotiated over IEEE Std 802.1X
        00-0F-AC:6 - PSK
        00-0F-AC:11 - Authentication negotiated over IEEE Std 802.1X using a Suite B compliant EAP method supporting SHA-256
        00-0F-AC:14 - Authentication negotiated over IEEE Std 802.1X
        00-0F-AC:16 - Authentication negotiated over IEEE Std 802.1X

    SHA-384
        00-0F-AC:12 - Authentication negotiated over IEEE Std 802.1X using a CNSA Suite compliant EAP method
        00-0F-AC:13 - FT authentication negotiated over IEEE Std 802.1X (PMKID for cached MPMK)
        00-0F-AC:15 - Authentication negotiated over IEEE Std 802.1X
        00-0F-AC:17 - Authentication negotiated over IEEE Std 802.1X
        00-0F-AC:19 - FT authentication using PSK (PMKID for cached MPMK)
        00-0F-AC:20 - PSK

    AMK Suite types not supported:
        00-0F-AC:7 - TDLS
        00-0F-AC:8 - SAE authentication
        00-0F-AC:9 - FT authentication over SAE
        00-0F-AC:10 - APPeerKey Authentication with SHA-256
        00-0F-AC:14 - Key management over FILS using SHA-256 and AES-SIV-256
        00-0F-AC:15 - Key management over FILS using SHA-384 and AES-SIV-512
        00-0F-AC:16 - FT authentication over FILS with SHA-256 and AES-SIV-256
        00-0F-AC:17 - FT authentication over FILS with SHA-384 and AES-SIV-512
    
Usage:
    python3 gen_pmkid.py <pmk> <aa> <spa>
        - pmk:    The PMK (or MPMK if using FT), as a hexadecimal string
        - aa:     The Authenticator Address (BSSID MAC address), as six groups of two hexadecimal digits, separated by hyphens, colons, or without a separator
        - spa:    The Supplicant Address (client MAC address), as six groups of two hexadecimal digits, separated by hyphens, colons, or without a separator

"""

__author__ = "Evan Wilkerson"
__version__ = "0.1.1"

import argparse
import re
import hmac
import hashlib


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: An object containing the parsed command-line arguments.

    Raises:
        ValueError: If 'pmk' is not a hexadecimal string.
        ValueError: If 'aa' is not a valid MAC address format.
        ValueError: If 'spa' is not a valid MAC address format.

    """
    # Create an ArgumentParser object for parsing command-line arguments
    parser = argparse.ArgumentParser(
        description="Calculate the PMKID."
    )

    # Add the 'pmk' argument to the parser, specifying it as a required hexadecimal string
    parser.add_argument(
        "pmk", type=str, help="The pairwise master key (PMK), or master PMK (MPMK) if using FT, as a hexadecimal string"
    )
    # Add the 'aa' argument to the parser, specifying it as a required MAC address string
    parser.add_argument(
        "aa",
        type=str,
        help="The Authenticator Address (BSSID MAC address), as six groups of two hexadecimal digits, separated by hyphens, colons, or without a separator",
    )
    # Add the 'spa' argument to the parser, specifying it as a required MAC address string
    parser.add_argument(
        "spa",
        type=str,
        help="The Supplicant Address (client MAC address), as six groups of two hexadecimal digits, separated by hyphens, colons, or without a separator",
    )

    # Parse the command-line arguments and store them in the 'args' variable
    args = parser.parse_args()

    # Compile a regular expression pattern for matching hexadecimal strings
    hex_regex = re.compile(r"^[0-9a-fA-F]+$")
    # Compile a regular expression pattern for matching MAC addresses
    mac_regex = re.compile(
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$"
    )

    # Check if the 'pmk' argument is a hexadecimal string
    if not hex_regex.match(args.pmk):
        raise ValueError("The PMK must be a hexadecimal string.")
    # Check if the 'aa' argument is a valid MAC address
    if not mac_regex.match(args.aa):
        raise ValueError("The AA must be a valid MAC address.")
    # Check if the 'spa' argument is a valid MAC address
    if not mac_regex.match(args.spa):
        raise ValueError("The SPA must be a valid MAC address.")

    # Return the parsed command-line arguments
    return args


def calculate_pmkids(pmk: bytes, aa: bytes, spa: bytes) -> tuple:
    """
    Calculate PMKIDs for the given PMK (Pairwise Master Key), AA (Authenticator Address),
    and SPA (Supplicant Address).

    Parameters:
        pmk (bytes): The Pairwise Master Key used in the calculation.
        aa (bytes): The Authentication Algorithm identifier.
        spa (bytes): The Synchronization Point Address.

    Returns:
        tuple: A tuple containing three PMKIDs calculated using different hash algorithms.
               The PMKIDs are strings of 32 hexadecimal characters each.

    """
    # Define the label used for PMKID calculation.
    PMKID_LABEL = bytes("PMK Name", "ascii")

    # Calculate PMKID using SHA-1 hash algorithm.
    pmkid_sha1 = hmac.new(pmk, PMKID_LABEL + aa + spa, hashlib.sha1).hexdigest()[:32]
    # Calculate PMKID using SHA-256 hash algorithm.
    pmkid_sha256 = hmac.new(pmk, PMKID_LABEL + aa + spa, hashlib.sha256).hexdigest()[:32]
    # Calculate PMKID using SHA-384 hash algorithm.
    pmkid_sha384 = hmac.new(pmk, PMKID_LABEL + aa + spa, hashlib.sha384).hexdigest()[:32]

    # Return the calculated PMKIDs as a tuple.
    return pmkid_sha1, pmkid_sha256, pmkid_sha384


def main():
    """
    Main entry point of the script

    """
    try:
        # Parse command-line arguments
        arguments = parse_arguments()

        # Convert the arguments from the command line to bytes
        pmk = bytes.fromhex(arguments.pmk)
        spa = bytes.fromhex(arguments.spa.replace(":", "").replace("-", ""))
        aa = bytes.fromhex(arguments.aa.replace(":", "").replace("-", ""))

        # Calculate the PMKIDs using the provided input
        pmkid_sha1, pmkid_sha256, pmkid_sha384 = calculate_pmkids(pmk, aa, spa)

        # Print the PMKIDs
        print()
        print(f"PMKID_SHA1:    {pmkid_sha1}")
        print(f"PMKID_SHA256:  {pmkid_sha256}")
        print(f"PMKID_SHA384:  {pmkid_sha384}")

    except ValueError as e:
        # Handle ValueError exceptions
        print(e)

    except Exception as e:
        # Handle any other unexpected exceptions
        print(f"An unexpected error has occured: {e}")


if __name__ == "__main__":
    main()
