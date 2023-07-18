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
