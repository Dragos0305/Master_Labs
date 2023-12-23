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
    return s + (16 - len(s) % 16) * (16 - len(s) % 16)
 
def unpad(s):
    return s[:-ord(s[len(s)-1:])]
 
# we admit the handshake produce a secret key for the session
# of course we do not have any HMAC etc .. but there are not usefull in this attack
# we can use this function without having access to the secret key
def encrypt(msg, iv_p=None):
    raw = pad(msg).encode()
    if iv_p is None:
        iv = Random.new().read(AES.block_size)
    else:
        iv = iv_p
    global key
    key = Random.new().read(AES.block_size)
    cipher = AES.new('V38lKILOJmtpQMHp'.encode(), AES.MODE_CBC, iv)
    return cipher.encrypt(raw)
 
"""
    The PoC of BEAST attack -
    Implementation of the cryptographic path behind the attack
    - the attacker can retrieve the request send be the client 
    - but also make the client send requests with the plain text of his choice
"""
 
def xor_strings(xs, ys, zs):
    return b"".join(chr(x ^ y ^ z).encode() for x, y, z in zip(xs, ys, zs))
 
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
    known_so_far = b"ID="
 
    # retrieve all the bytes of the cookie (in total 16 bytes, all fit in one block)
    for t in range(len(SECRET_COOKIE)):
        padding = 16 - len(known_so_far) - 1

        # Sent padding + what_i_know
        for i in range(0,256):

            # TODO send first request
            first_request_result = send_request(b'A' * padding + known_so_far) 
            # TODO send second request
            second_request_result = send_request(b'A'* padding + known_so_far)
            # # TODO craft and send third request
            original = split_len(second_request_result, 16)

            # # GUESS XOR VI XOR C_I_1 build by the attacker
            print(len(second_request_result))
            vector_init = second_request_result
            print(len(vector_init))

            
            previous_cipher = first_request_result
            print(len(previous_cipher))
            p_guess = b'A' * padding + known_so_far + chr(i).encode()
            
            xored = b''
            for i in range(16):
                xored += int.to_bytes(previous_cipher[i] ^ vector_init[i] ^ p_guess[i],1,"big")
           # xored = xor_block( vector_init, previous_cipher, p_guess)
            print("Xored is ", xored, " and len is ", len(xored)) 
            third_request_result = send_request(xored)
            # TODO check if the guess is correct

            result = split_len(third_request_result, 16)
            if original[0] == result[0]: # change condition here
                known_so_far += chr(i).encode()
                break
            elif i == 255:
                print("Unable to find the char...")
                return known_so_far.decode()
    return known_so_far.decode()
 
 
# the attacker doesn't know the cookie
secret = run_three_request()
 
print("\n" + secret)