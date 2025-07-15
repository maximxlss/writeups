import random


masks = eval(input())
body = bytes(eval(input()))

boxes = []
fixed_rng = random.Random()
fixed_rng.seed(1234)
for _ in range(8):
    box_permutation = list(range(256))
    fixed_rng.shuffle(box_permutation)
    box = list(box_permutation)
    boxes.append(box)

rev_boxes = []
for box in boxes:
    revbox = [0] * 256
    for i, x in enumerate(box):
        revbox[x] = i
    rev_boxes.append(revbox)


def encode(key, c, i):
    key = (int.from_bytes(key, "little") + i).to_bytes(8, "little")
    for i in range(8):
        c = (boxes[i][c] + key[i]) % 256
    c ^= 1
    for i in range(7, -1, -1):
        c = rev_boxes[i][c - key[i]]
    return c


xexes = [0] * 8
deltas = [0] * 8
for i, d in enumerate(masks[0]):
    if d is not None:
        xexes[i] = 0
        deltas[i] = d
for i, d in enumerate(masks[1]):
    if d is not None:
        xexes[i] = 1
        deltas[i] = d
for i, d in enumerate(masks[2]):
    if d is not None:
        xexes[i] = 2
        deltas[i] = d


nums = 0

for it in range(256**3):
    key = [0] * 8
    numsv = nums.to_bytes(4, "little")
    for i in range(8):
        key[i] = rev_boxes[0][(numsv[xexes[i]] + deltas[i] - i) % 256]
    key.reverse()
    for i, v in enumerate(b"12345678"):
        if encode(key, v, i) != body[i]:
            break
    else:
        print(key)
        exit()
    nums += 1
