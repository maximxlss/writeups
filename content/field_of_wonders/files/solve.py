import itertools
from sage.all import *
from concurrent.futures import ThreadPoolExecutor, as_completed

from os import urandom
import nacl.pwhash
import nacl.utils
from nacl import secret
from poly_gen import generate_data, get_auxtext

from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
from Crypto.Cipher.ChaCha20 import _HChaCha20
from Crypto.Hash.Poly1305 import Poly1305_MAC

import ast

from pwn import *


def forge_for_keys(right_keys):
    nonce = urandom(24)
    chacha20_poly1305_nonce = b'\x00\x00\x00\x00' + nonce[16:]

    def extract_poly1305_params(key):
        key = _HChaCha20(key, nonce[:16])
        r, s, _ = ChaCha20._derive_Poly1305_key_pair(key, chacha20_poly1305_nonce)

        r = int.from_bytes(r, 'little')
        s = int.from_bytes(s, 'little')

        r &= 0x0ffffffc0ffffffc0ffffffc0fffffff

        return r, s

    points = []

    for key in right_keys:
        r, s = extract_poly1305_params(key)
        points.append((r, -s % 2 ** 128))

    N = 2 ** 130 - 5
    PR = PolynomialRing(Zmod(N), "x")
    x = PR.gen()

    poly = PR.lagrange_polynomial(points)
    points = [p[0] for p in points]

    r, s = extract_poly1305_params(key)

    assert (int(poly(r)) + s) % 2 ** 128 == 0

    text = generate_data(poly, points, 5)

    encoded_ciphertext = nonce + text + b'\0' * 16

    
    for key in right_keys:
        secret.Aead(key).decrypt(encoded_ciphertext)

    # def check(r, s, data):
    #     new_mac = Poly1305_MAC(r, s, data)
    #     print(new_mac.digest())

    # aux_text = get_auxtext(len(text))
    # print(len(text))
    # print(f"{aux_text = }")


    # def recover_poly(text, r):
    #     value = 0
    #     for i in range(0, len(text), 16):
    #         c = int.from_bytes(text[i:i + 16] + bytes([1]), 'little')
    #         value = (value + c) * r % N
    #     return value

    # print(text + aux_text)

    # print("test")
    # r, s = extract_poly1305_params(right_keys[0])
    # assert (int(poly(r)) + s) % 2 ** 128 == 0
    # assert (recover_poly(text + aux_text, r) + s) % 2 ** 128 == 0
    # r, s, _ = ChaCha20._derive_Poly1305_key_pair(right_keys[0], chacha20_poly1305_nonce)
    # check(r, s, text + aux_text)

    return encoded_ciphertext


def compute_key_for_phrase(args):
    """Helper function to compute a single key for a phrase"""
    phrase, salt = args
    key = nacl.pwhash.argon2id.kdf(
        size=secret.Aead.KEY_SIZE,
        password=phrase.encode(),
        salt=salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
    )
    return key


def phrases_to_keys(salt, phrases):
    """Multithreaded version of phrases_to_keys"""
    import os
    max_workers = min(32, (os.cpu_count() or 1) + 4)  # Limit workers to avoid excessive memory usage
    
    # Prepare arguments for the worker function
    args_list = [(phrase, salt) for phrase in phrases]
    
    keys = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_index = {executor.submit(compute_key_for_phrase, args): i 
                          for i, args in enumerate(args_list)}
        
        # Collect results in order
        results = [None] * len(phrases)
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            results[index] = future.result()
        
        keys = results
    
    return keys


def binsearch_predicate(keys, l, r):
    subset = keys[l:r]
    msg = forge_for_keys(subset)
    pi.sendline(b'1')
    pi.sendline(msg.hex())
    r = pi.recvuntil([b'You guessed the correct word, congratulations!', b'Unfortunately not'])
    return b'correct' in r


def binsearch(salt, keys):
    l, r = 0, len(keys)

    while r - l > 1:
        print(l, r)
        mid = (l + r) // 2
        if binsearch_predicate(keys, l, mid):
            r = mid
        else:
            l = mid
    
    return l


def one_game():
    pi.recvuntil(b'Sponsor of this game is:\n')
    salt = bytes.fromhex(pi.recvline().strip().decode())
    pi.recvuntil(b'And a little hint on which words can be in the phrase:\n')
    guessable = ast.literal_eval(pi.recvline().strip().decode())
    phrases = list(itertools.product(guessable, repeat=3))
    
    phrases = [' '.join(phrase) for phrase in phrases]

    keys = phrases_to_keys(salt, phrases)

    print("generated keys")

    i = binsearch(salt, keys)

    phrase = phrases[i]

    print(phrase)

    pi.sendline(b'2')
    pi.sendline(phrase)

    pi.recvuntil(b'And... We have a winner!', timeout=2)


# pi = process(["python", "challenge.py"])
pi = remote("158.160.164.131", 8888)

for i in range(35):
    one_game()
    print("finished", i + 1)

pi.interactive()

