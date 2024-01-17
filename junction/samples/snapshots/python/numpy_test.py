import snapshot
import numpy as np
import sys

print("Starting numpy snapshot test")

size = 100

m1 = np.random.rand(size, size)
m2 = np.random.rand(size, size)

res = np.dot(m1, m2)

if len(sys.argv) > 1:
    elf = "/tmp/junction.elf"
    metadata = "/tmp/junction.metadata"
    
    if len(sys.argv) > 3:
        metadata = sys.argv[2]
        elf = sys.argv[3]
    
    ret = snapshot.snapshot(elf, metadata)
    if ret:
        print("Snapshotted!")
    else:
        print("Restored!")

res1 = np.dot(m1, m2)

if np.array_equal(res, res1):
    print("OK: Matrices are the same")
else:
    print("ERR: Matricies differ");
