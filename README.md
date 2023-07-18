## Contents
* [Overview](https://github.com/Bodayngo/master-session-key/blob/development/README.md#overview)
* [Usage](https://github.com/Bodayngo/master-session-key/blob/development/README.md#usage)
* [Alternatives](https://github.com/Bodayngo/master-session-key/blob/development/README.md#alternatives)
* [References](https://github.com/Bodayngo/master-session-key/blob/development/README.md#references)

## Overview
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
$ python3 get_msk.py radiussharedsecret 94f77e05a8610c7a2186f1a4d8d6fa328192619455dee03142669e1a1ff583b3593284d31c985edc78892a0414e54e527d55 9d662d78d01092890b516531291542373db99da21ac9d8f58d8e2583318486a911c7edfe7f17457f81c6a4169948936dabe4 a0fcd2bd28f624724726135fc97d22d9

Master Session Key (MSK):  7dca16f8d83d5d34d39034654c9bd84cc57beae90c7639b0291b7e0846b9dffa501097cddf665fccfac7933504e86325461ded33ba080066ab1d6ed314950c58
```


## Alternatives
The radsniff tool (available with freeradius) can also be used to calculate the MSK by decrypting the MS-MPPE-Recv-Key and MS-MPPE-Send-Key when passed a packet capture file containing the RADIUS authentication exchange and the RADIUS shared secret. Once decrypted, concatenate the two (MS-MPPE-Recv-Key + MS-MPPE-Send-Key) to get the MSK.
```
$ radsniff -x -I example_wired_radius.pcap -s radiussharedsecret

----- output omitted for brevity -----

2023-07-17 13:08:17.707659 (20) Access-Accept Id 39 example_wired_radius.pcap:10.1.10.1:47554 <- 10.1.20.60:1812 +0.185 +0.000
        User-Name = "client.lab.local"
        Framed-MTU = 994
        Session-Timeout = 3600
        Tunnel-Type:0 = VLAN
        Tunnel-Medium-Type:0 = IEEE-802
        Tunnel-Private-Group-Id:0 = "100"
        EAP-Message = 0x03c50004
        Message-Authenticator = 0x17ea80ec815ac50669da3acde6fb6df1
        MS-MPPE-Send-Key = 0x501097cddf665fccfac7933504e86325461ded33ba080066ab1d6ed314950c58
        MS-MPPE-Recv-Key = 0x7dca16f8d83d5d34d39034654c9bd84cc57beae90c7639b0291b7e0846b9dffa
        Authenticator-Field = 0xcf228335f114bb4e1fd555b2a2ab5bac
Done reading packets (example_wired_radius.pcap)
Done sniffing
```


## References
* [802.11-2020 Standard](https://ieeexplore.ieee.org/document/9363693)
  * Sub-clause 12.7.1.3 - Pairwise key hierarchy
  * Sub-clause 12.7.1.6 - FT key hierarchy
* [RFC 3748 - EAP](https://datatracker.ietf.org/doc/html/rfc3748)
  * Section 7.10 - Key Derivation
* [RFC 5216 - EAP-TLS Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc5216)
  * Section 2.3 - Key Hierarchy
* [RFC 2548 - Microsoft Vendor-specific RADIUS Attributes](https://datatracker.ietf.org/doc/html/rfc2548)
  * Section 2.4.2 - MS-MPPE-Send-Key
  * Section 2.4.3 - MS-MPPE-Recv-Key
