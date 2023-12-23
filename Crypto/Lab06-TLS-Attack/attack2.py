#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pdb
    
'''
    TLS BEAST attack - PoC
    Implementation of the cryptographic path behind the attack
'''
    
import random
import binascii
import sys
from Crypto.Cipher import AES
from Crypto import Random
    
SECRET_COOKIE = "ID=3ef729ccf0cc5"
BLOCK_LENGTH = 16
    
last_iv = None
    
"""
    AES-CBC
    function encrypt, decrypt, pad, unpad
    You can fix the IV in the function encrypt() because TLS 1.0 fix the IV
    for the second, third... request (to gain time)
"""
    
def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    
def unpad(s):
    return s[:-ord(s[len(s)-1:])]
    
# we admit the handshake produce a secret key for the session
# of course we do not have any HMAC etc .. but there are not usefull in this attack
# we can use this function without having access to the secret key
def encrypt(msg, iv_p=None):
    raw = pad(msg)
    if iv_p is None:
        iv = Random.new().read(AES.block_size)
    else:
        iv = iv_p
    global key
    key = Random.new().read(AES.block_size)
    cipher = AES.new('V38lKILOJmtpQMHp', AES.MODE_CBC, iv)
    return cipher.encrypt(raw)
    
"""
    The PoC of BEAST attack -
    Implementation of the cryptographic path behind the attack
    - the attacker can retrieve the request send be the client 
    - but also make the client send requests with the plain text of his choice
"""
    
def xor_strings(xs, ys, zs):
    return "".join(chr(ord(x) ^ ord(y) ^ ord(z)) for x, y, z in zip(xs, ys, zs))
    
def xor_block(vector_init, previous_cipher, p_guess):
    xored = xor_strings(vector_init, previous_cipher, p_guess)
    return xored
    
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]
    
def send_request(msg):
    global last_iv
    enc = encrypt(msg, last_iv)
    last_iv = enc[-BLOCK_LENGTH:]
    return enc
    
    
# the PoC start here
def run_three_request():
    secret = []
    
    # the part of the request the atacker knows, can be null
    known_so_far = "ID="
    
    # retrieve all the bytes of the cookie (in total 16 bytes, all fit in one block)
    for t in range(len(SECRET_COOKIE)):
        padding = 16 - len(known_so_far) - 1
    
        for i in range(0,256):
            # TODO send first request
            send_request('A' * padding) 
            # TODO send second request
    
            # TODO craft and send third request
    
            # TODO check if the guess is correct
            if False: # change condition here
                known_so_far += chr(i)
                break
            elif i == 255:
                print("Unable to find the char...")
                return known_so_far
    return known_so_far
    
    
# the attacker doesn't know the cookie
secret = run_three_request()
    
print("\n" + secret)

