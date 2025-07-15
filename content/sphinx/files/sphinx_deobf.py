import struct
import os
import base64
from sboxes import SBOXES

ROTATION_SCHEDULE = [16, 16, 8, 8, 16, 16, 24, 24]

def rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def unpack_ints(b):
    if len(b) % 4 != 0:
        raise ValueError()
    return list(struct.unpack(">%dI" % (len(b) // 4), b))

def pack_ints(xs):
    return struct.pack(">%dI" % len(xs), *xs)

class Khafre:
    def __init__(self, key: bytes, n_rounds=16):
        if not (8 <= n_rounds <= 64 and n_rounds % 8 == 0):
            raise ValueError()
        self.n_rounds = n_rounds

        if not (len(key) >= 8 and len(key) % 8 == 0) :
            raise ValueError()

        self.key_words = unpack_ints(key)
        self.sboxes = SBOXES

        n_key_dwords = len(self.key_words) // 2
        if n_key_dwords == 0:
             raise ValueError()

        if ((self.n_rounds // 8) + 1) % n_key_dwords != 0:
            raise ValueError()


    def encrypt(self, pt: bytes, debug_trace=False) -> bytes:
        if len(pt) != 8:
            raise ValueError()
        if debug_trace:
            self.trace = [None] * self.n_rounds

        left, right = unpack_ints(pt)

        key_words = self.key_words
        sboxes = self.sboxes

        n_octets = self.n_rounds // 8

        key_index = 0
        octet_index = 0

        while True:
            if key_index >= len(key_words):
                key_index = 0

            left  = (left  ^ rotr(key_words[key_index], octet_index)) & 0xFFFFFFFF
            right = (right ^ rotr(key_words[key_index+1], octet_index)) & 0xFFFFFFFF
            key_index += 2

            if octet_index >= n_octets:
                break

            sbox = sboxes[octet_index]
            for i in range(8):
                sbox_index = left & 0xff
                sbox_val = sbox[sbox_index]

                if debug_trace:
                    self.trace[octet_index * 8 + i] = (right, left, sbox_val)

                right = (right ^ sbox_val) & 0xFFFFFFFF
                left = rotr(left, ROTATION_SCHEDULE[i])
                left, right = right, left
                

            octet_index += 1

        return pack_ints([left, right])

    def decrypt(self, ct: bytes) -> bytes:
        if len(ct) != 8:
            raise ValueError()
        left, right = unpack_ints(ct)

        key_words = self.key_words
        sboxes = self.sboxes

        n_octets = self.n_rounds // 8

        n_key_dwords = len(key_words) // 2
        key_index = (n_octets % n_key_dwords) * 2


        octet_index = n_octets

        while True:
            left  = (left  ^ rotr(key_words[key_index], octet_index)) & 0xFFFFFFFF
            right = (right ^ rotr(key_words[key_index+1], octet_index)) & 0xFFFFFFFF

            if octet_index == 0:
                break

            key_index -= 2
            if key_index < 0:
                key_index = len(key_words) - 2

            octet_index -= 1

            sbox = sboxes[octet_index]
            for i in reversed(range(8)):
                left, right = right, left
                left = rotl(left, ROTATION_SCHEDULE[i])
                right = (right ^ sbox[left & 0xff]) & 0xFFFFFFFF

        return pack_ints([left, right])
