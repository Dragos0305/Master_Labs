# Import modules
import base64
from Crypto.PublicKey import RSA    
from Crypto.Util.number import GCD, inverse
from Crypto.Cipher import PKCS1_OAEP

# Function for file handling
def get_file_content(filename : str) -> bytes:
    with open(filename, "rb") as encrypted_file:
        content = encrypted_file.read()
        encrypted_file.close()
        return content


# Function de construct private_key
def construct_private_key(N, e, p, q):
    phi = ((q-1) * (p-1)) % N
    d = inverse(e,phi)
    return RSA.construct((N,e,d))

# Function to decrypt RSA OAEP
def decrypt(private_key, ciphertext):
    decryptor = PKCS1_OAEP.new(private_key)
    print(decryptor.decrypt(ciphertext).decode(), end='')


if __name__ == "__main__":
    # Read ciphertexts
    for_alice = get_file_content("for_alice.enc")
    for_bob = get_file_content("for_bob.enc")

    # Read and store alice public key
    alice_pub_key_base64 = get_file_content("alice.pubkey")
    alice_pub_key = RSA.import_key(alice_pub_key_base64)

    # Read and store bob public key
    bob_pub_key_base64 = get_file_content("bob.pubkey")
    bob_pub_key =  RSA.import_key(bob_pub_key_base64)

    # Find common p
    p = GCD(alice_pub_key.n, bob_pub_key.n)

    # Compute alice private_key and decrypt message
    alice_private_key = construct_private_key(alice_pub_key.n, alice_pub_key.e, p, alice_pub_key.n // p)
    decrypt(alice_private_key, base64.b64decode(for_alice.decode()))

    # Compute bob private_key and decrypt message
    bob_private_key = construct_private_key(bob_pub_key.n, bob_pub_key.e, p, bob_pub_key.n // p)
    decrypt(bob_private_key, base64.b64decode(for_bob.decode()))

    print()



