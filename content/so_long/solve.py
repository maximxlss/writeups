import io
from itertools import pairwise
import time
from PIL import Image
import numpy as np
from base64 import b64decode
from pwn import remote, context
from numba import njit


# context.log_level = "DEBUG"

t = time.time()

pi = remote("20.80.240.190", 4442)


# this is as small as possible (but still contains most executed code)
# it's because many things are not supported properly by numba jit
@njit
def perf_sensitive(comes_from, queue, blocked, end_pos):
    while queue:
        back_queue = []  # this would be the positions to check
        # on the next iteration

        for x, y in queue:
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    # this does one extra check for (x, y)
                    # but it doesn't matter
                    nx, ny = x + dx, y + dy
                    if (
                        0 <= nx < blocked.shape[0]  # check dim
                        and 0 <= ny < blocked.shape[1]
                        and not blocked[nx, ny]  # and block
                    ):
                        # so if we're here the cell is to be visited
                        blocked[nx, ny] = 1
                        # and the closest path to it is from the current pos
                        comes_from[nx, ny] = [x, y]
                        if end_pos == (nx, ny):
                            return
                        back_queue.append((nx, ny))

        # swap queues
        queue = back_queue


for i in range(1000):
    print(pi.recvuntil(f"Round {i + 1}/1000:"))  # print to see progress
    pi.readline()
    img_b64 = pi.readline()
    print(time.time() - t, "in network stuff")
    t = time.time()

    img = b64decode(img_b64)
    with open("maze.png", "wb") as f:  # save the image for debugging
        f.write(img)
    img = Image.open(io.BytesIO(img))  # method to open bytes with PIL

    img = np.array(img)  # switch over to numpy
    # this would be a 2d array with 3 numbers r, g, b in each entry

    # find first white pixel. it will be in the upper left corner
    # it's coordinates are the same as labyrinth cell step size
    white_pixels = (img == (255, 255, 255)).all(axis=2)
    first_white = np.where(white_pixels)[0]
    step = first_white[0]

    # split into boolean arrays for r, g and b
    r, g, b = [img[::step, ::step, i] == 255 for i in range(3)]

    # isolate the elements
    maze_walls = ~r & ~g & ~b
    maze_exits = r & ~g & ~b
    maze_players = ~r & g & ~b

    # can save them like this for debugging
    # Image.fromarray(maze_walls).save("maze_walls.png")
    # Image.fromarray(maze_exit).save("maze_exit.png")
    # Image.fromarray(maze_player).save("maze_player.png")

    # np.where with some converting to get the positions as np arrays
    # and check that there is one exit and one player
    assert len(np.argwhere(maze_players)) == 1
    start_pos = np.argwhere(maze_players)[0]
    assert len(np.argwhere(maze_exits)) == 1
    end_pos = np.argwhere(maze_exits)[0]

    # comes_from is 2d with 2-number entries,
    # positions from where the closest path to this cell from start lies
    comes_from = np.zeros((*maze_walls.shape[:2], 2), dtype=np.int64)
    queue = [tuple(start_pos)]  # queue starts out at start pos
    blocked = np.copy(maze_walls)  # auto block walls

    comes_from[*start_pos] = (-1, -1)
    blocked[*start_pos] = 1  # and start pos

    # now into the slow part (not slow with numba)
    perf_sensitive(comes_from, queue, blocked, tuple(end_pos))

    # backtrack the path from the end
    path = []

    pos = end_pos
    while (comes_from[*pos] != (-1, -1)).all():  # while not at start
        path.append(pos)
        pos = comes_from[*pos]  # backtrack
    path.append(start_pos)
    path.reverse()

    # output path for debugging
    # with open("path.txt", "w") as f:
    #     for x, y in path:
    #         print(x, y, file=f)

    # turn into words
    s = []
    for _from, _to in pairwise(path):
        d = _to - _from
        match tuple(reversed(d)):
            case (-1, 0):
                w = "left"
            case (-1, 1):
                w = "down-left"
            case (0, 1):
                w = "down"
            case (1, 1):
                w = "down-right"
            case (1, 0):
                w = "right"
            case (1, -1):
                w = "up-right"
            case (0, -1):
                w = "up"
            case (-1, -1):
                w = "up-left"
            case _:
                raise ValueError(d)
        s.append(w)
    s = " ".join(s)

    # done
    print(time.time() - t, "calculating")
    t = time.time()

    pi.sendline(s)

pi.interactive()
