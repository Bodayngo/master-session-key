# master-session-key

## Description
The Master Session Key (MSK) is a key that is derived between a supplicant (wireless client) and authentication server (RADIUS server) which is then exported by the EAP method and sent to the authenticator (access point) in a RADIUS Access-Accept message so that it can be used to derive the PMK, which is subsequently used to derive the PTK for unicast encryption.

The get_msk.py script calculates the Master Sesssion Key (MSK) for an 802.1X/EAP wireless authentication when passed the following input: 
* The RADIUS shared secret that is configured on the access point and RADIUS server (ASCII string)
* The MS-MPPE-Recv-Key in the RADIUS Access-Accept (hexidecimal string)
* The MS-MPPE-Send-Key in the RADIUS Access-Accept (hexidecimal string)
* The Request-Authenticator in the RADIUS Access-Request prior to the Access-Accept (hexidecimal string)
