## Description
The Master Session Key (MSK) is a key that is derived between a supplicant (wireless client) and authentication server (RADIUS server) which is then exported by the EAP method and sent to the authenticator (access point) in a RADIUS Access-Accept message so that it can be used to derive the PMK, which is subsequently used to derive the PTK for unicast encryption.

The get_msk.py script calculates the Master Sesssion Key (MSK) for an 802.1X/EAP wireless authentication when passed the following input: 
* The RADIUS shared secret that is configured on the access point and RADIUS server (ASCII string)
* The MS-MPPE-Recv-Key field in the RADIUS Access-Accept (hexidecimal string)
* The MS-MPPE-Send-Key field in the RADIUS Access-Accept (hexidecimal string)
* The Request-Authenticator field in the RADIUS Access-Request prior to the Access-Accept (hexidecimal string)

![ms-mppe-keys](https://github.com/Bodayngo/master-session-key/assets/97417803/c3f7c56b-f844-4214-b753-cab5e3c57b45)

![request-authenticator](https://github.com/Bodayngo/master-session-key/assets/97417803/f2e06f66-32b7-41b1-96c5-e9791ef93e12)

## Usage
```
# Syntax
$ python3 get_msk.py <radius_shared_secret> <ms-mppe-recv-key> <ms-mppe-send-key> <request-authenticator>

# Example
$ python3 get_msk.py radiussharedsecret e05f79561ade51446bacf921b68fc25a05ac9268d55f686860c6a04214586152183adcfb89b865f552da3b1af7f90445e871 ee7a3214ebda071b552a41dbcf8e42fdbd5189eaa445f95ff310a364fb066962000d303254a2e040d047f0d67dce9c6e1e7a 13bfb399bb1baae150bab9afcf5eb1c2

Master Session Key (MSK):  96a8b3965f4615307d13812251e21a7970ffcf9bf4c4bc6543d0008c0e6fdce2070b050e3d294ca627b0e98dd731f3e50f09a1912d6b073ce40d13e620a26cef
```

## Alternatives

## References
* 802.11-2020 Standard
  * Sub-clause 12.7.1.3 - Pairwise key hierarchy
  * Sub-clause 12.7.1.6 - FT key hierarchy
* RFC 3748 - EAP (https://datatracker.ietf.org/doc/html/rfc3748)
  * Section 7.10 - Key Derivation
* RFC 5216 - EAP-TLS Authentication Protocol (https://datatracker.ietf.org/doc/html/rfc5216)
  * Section 2.3 - Key Hierarchy
* RFC 2548 - Microsoft Vendor-specific RADIUS Attributes (https://datatracker.ietf.org/doc/html/rfc2548)
  * Section 2.4.2 - MS-MPPE-Send-Key
  * Section 2.4.3 - MS-MPPE-Recv-Key
