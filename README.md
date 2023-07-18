# master-session-key

## Description
The Master Session Key (MSK) is a key that is derived between a supplicant (wireless client) and authentication server (RADIUS server) which is then exported by the EAP method and sent to the authenticator (access point) in a RADIUS Access-Accept message so that it can be used to derive the PMK, which is subsequently used to derive the PTK for unicast encryption keys.

The get_msk.py script calculates the Master Sesssion Key (MSK) for an 802.1X/EAP wireless authentication when passed the following input: 
