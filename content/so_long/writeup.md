---
title: so_long (Akasec CTF 2024; misc)
date: 2024-06-12
---
> Author: hel-makh
> How long will it take you to escape the maze? Find the shortest path to the exit of the maze.

Solve script: [./solve.py](https://github.com/maximxlss/writeups/blob/v4/content/so_long/solve.py)

### Time for programming
Let's see the netcat intro:
```
Welcome to so_long!

Your goal is to find the shortest path from the start point (green square) to the end point (red square).
You can move up, down, left, right, up-left, up-right, down-left, and down-right.
Insert your moves separated by spaces. For example: "up down-right right down".

Good luck!

Round 1/1000: <base64_image>
Enter your moves: 
```
Here's an example of a maze:
![[maze.png]]
Doing some research in an image editor (for example, [this](https://marketplace.visualstudio.com/items?itemName=Tyriar.luna-paint)), we can see the general structure of the image. Now we can begin writing the script.
Let's start by implementing the IO with the server, using pwntools, as you always should:
```python
pi = remote("20.80.240.190", 4442)
for i in range(1000):
	print(pi.recvuntil(f"Round {i + 1}/1000:")) # print to see progress
	pi.readline()
	img_b64 = pi.readline()
	# <maze processing and solving>
	pi.sendline(s)

pi.interactive()
```
Now to the important stuff.
### Processing the image
Looking it up online, here's how we can load the image:
```python
img_data = b64decode(img_b64)
img_obj = Image.open(io.BytesIO(img_data))
```
Nice! Now, since we are working with quite big data, it would be appropriate to use Numpy for processing. Let's see how we can take advantage of it's awesome interface. First of all, convert the image into an array (using the first-class support for Numpy in the Pillow library):
```python
img = np.array(img_obj)
```
Now we can calculate the size of one labyrinth cell by checking the first white pixel:
```python
white_pixels = (img == (255, 255, 255)).all(axis=2)
first_white = np.where(white_pixels)[0]
step = first_white[0]
```
If this is confusing to you, that's completely understandable. I recommend experimenting and googling to get used to Numpy, it really makes processing data fast and satisfying.
Now we split the image into channels while also respecting cell size:
```python
r, g, b = [img[::step, ::step, i] == 255 for i in range(3)]
```
Now we can do this to easily get all the elements of the maze:
```python
maze_walls = ~r & ~g & ~b 
maze_exits = r & ~g & ~b
maze_players = ~r & g & ~b
```
Let's get the starting and ending positions:
```python
start_pos = np.argwhere(maze_players)[0]
end_pos = np.argwhere(maze_exits)[0]
```
With this, the image is processed and we are ready to solve the maze.
### Solving the maze
The problem at hand is called "pathfinding". There are numerous ways to do that, although the main ideas are the same. In this case, when the maze is simple and we aren't concerned with speed too much, all algorithms boil down to just BFS, or Breadth-First Search. Here's how it goes:
1. Create a boolean array of the same shape as the maze itself. Fill it with ones where there is a wall in the maze, and also where the starting position is:
	 ```python
	 blocked = np.copy(maze_walls)
	 blocked[*start_pos] = 1
	 ```
	 This array will represent the cells that you don't want or can't go to, such as walls and already visited positions.
2. Create an array of int pairs (positions), of the same shape as the maze. Set it to a special value, like `(-1, -1)`, at the starting position:
	```python
	comes_from = np.zeros((*maze_walls.shape[:2], 2), dtype=np.int64)
	comes_from[*start_pos] = (-1, -1)
	```
	This array, at position $p$, will store some neighbouring position from which it is the fastest to get to $p$ on the path from the starting point to $p$. This information will allow us to backtrack from the ending position to get the desired shortest path.
3. Start with the starting position as the only one to process, and continue until the ending position has been reached. On every iteration, process all the pending positions by going to every unblocked neighbour and filling out the array appropriately, after which you need to store those neighbours to be processed on the next iteration. We do this with two queues and some simple logic:
	```python
	queue = [tuple(start_pos)]
	while queue:
		back_queue = []
		for x, y in queue:
			for dx in (-1, 0, 1):
				for dy in (-1, 0, 1):
					nx, ny = x + dx, y + dy
					if (
						0 <= nx < blocked.shape[0]
						and 0 <= ny < blocked.shape[1]
						and not blocked[nx, ny]
					):
						blocked[nx, ny] = 1
						comes_from[nx, ny] = [x, y]
						if end_pos == (nx, ny):
							return
						back_queue.append((nx, ny))
		# swap queues
		queue = back_queue
	```
	On every iteration, the positions checked turn out to be all the same amount of steps from the start. Vice versa, those are all the positions that are that number of steps from the start. It's not hard to see that `comes_from` traces out the shortest path in reverse.
4. Now that all the needed positions are filled, we can simply backtrack from the ending point until we reach the start and get the path:
	```python
	path = []
	pos = end_pos
	while (comes_from[*pos] != (-1, -1)).all():
		path.append(pos)
		pos = comes_from[*pos]
	path.append(start_pos)
	path.reverse()
	```
	With this the task is basically solved.
### Final touches
Let's convert the deltas between the pairs in path into words (respecting the weird coordinate system, arising from both Pillow and indexing peculiarities):
```python
s = []
for _from, _to in pairwise(path):
	d = _to - _from
	match tuple(reversed(d)):
		case (-1, 0):
			w = "left"
		# <insert all the other cases>
		case _:
			raise ValueError(d)
	s.append(w)
s = " ".join(s)
```
Solved! See [solve script](https://github.com/maximxlss/writeups/blob/v4/content/so_long/solve.py).
### Extra
This concludes solving the task, but not my writeup, as I tested out the timings and was _not_ satisfied with computing time close to IO expenses, so I took that as a perfect opportunity to try applying [Numba](https://numba.pydata.org/). Numba is an awesome framework, opening up both optimized cpu and _gpu (!)_ support _without leaving python!_
The most magical part about is just how easy it is to apply the Numba JIT and make your code run on par with compiled binaries. We just take the slowest lines of code and bring them out into a separate function, with a magic decorator:
```python
@numba.njit
def perf_sensitive(*args):
	...
```
And it works!

Or maybe it doesn't. The Numba JIT, although fast, is quite limited, so it's best to JIT only the parts that are actually run many times over and over. Even then you might encounter errors. If you do, read the traceback (the most common mistake is using different types in one list, which is unsupported). Even with those pitfalls, Numba is awesome.

This transformation makes maze-solving run in about 250 ms, cool!
