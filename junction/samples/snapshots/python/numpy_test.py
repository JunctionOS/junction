import numpy as np
import sys
import os
import signal

print("Starting numpy snapshot test")

size = 100

m1 = np.random.rand(size, size)
m2 = np.random.rand(size, size)

res = np.dot(m1, m2)

# wait for snapshot
os.kill(os.getpid(), signal.SIGSTOP)

print('restored')

res1 = np.dot(m1, m2)

if np.array_equal(res, res1):
    print("OK: Matrices are the same")
else:
    print("ERR: Matricies differ")
