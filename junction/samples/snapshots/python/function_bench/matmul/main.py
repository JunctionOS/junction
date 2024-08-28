import numpy as np
from time import time


def matmul(N):
    A = np.random.rand(N, N)
    B = np.random.rand(N, N)

    start = time()
    C = np.matmul(A, B)
    latency = time() - start

    return latency


def function_handler(request_json):
    N = request_json['N']
    latency = matmul(N)
    return "latency : " + str(latency)
