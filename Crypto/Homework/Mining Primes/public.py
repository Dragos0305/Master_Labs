from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util import number
import base64
from keys import alice_key, bob_key

FLAG = ### REDACTED ###

message_for_alice = FLAG[:len(FLAG)//2]
message_for_bob   = FLAG[len(FLAG)//2:]

alice_encryptor = PKCS1_OAEP.new(alice_key.publickey())
bob_encryptor = PKCS1_OAEP.new(bob_key.publickey())

for_alice_encrypted = alice_encryptor.encrypt(message_for_alice)
for_bob_encrypted   = bob_encryptor.encrypt(message_for_bob)

message_1 = base64.b64encode(for_alice_encrypted)
message_2 = base64.b64encode(for_bob_encrypted)

f = open('for_alice.enc', 'wb')
f.write(message_1)
f.close()

f = open('for_bob.enc', 'wb')
f.write(message_2)
f.close()

f = open('alice.pubkey', 'wb')
f.write(alice_key.publickey().exportKey())
f.close()

f = open('bob.pubkey', 'wb')
f.write(bob_key.publickey().exportKey())
f.close()
