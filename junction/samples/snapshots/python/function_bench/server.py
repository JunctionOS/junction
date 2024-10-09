from concurrent import futures
import logging
import grpc
import time
import sys
import os
import ctypes
import gc
import importlib
import json

libc = ctypes.CDLL(None)

parent = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, parent)

import helloworld_pb2
import helloworld_pb2_grpc

responses = ["record_response", "replay_response"]

def snapshot_prepare():
    sys.stdout.flush()
    for i in range(3):
        gc.collect()
    libc.malloc_trim(0)

class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def __init__(self, handler):
        self.handler = handler
        self.snapshotted = False
    
    def SayHello(self, request, context):        
        f = open("/serverless/chan0", "r+")
        msg = f.readline()
        
        if "SNAPSHOT_PREPARE" in msg:
            snapshot_prepare()
            msg = "OK"
            self.snapshotted = True
            f.write(msg)
            return helloworld_pb2.HelloReply(message=msg)

        json_req = json.loads(msg)

        start = time.time()
        self.handler(json_req)
        latency = time.time() - start

        # restore path
        if self.snapshotted:
            msg = "OK"
            f.write(" ")
            return helloworld_pb2.HelloReply(message=msg)

        msg = f"latency: {time}"
        f.write(msg)

        return helloworld_pb2.HelloReply(message=msg)


def serve(handler):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(handler), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    prog = sys.argv[1]
    if prog == "chameleon" or prog == "pyaes":
        prog += "1"

    handler = importlib.import_module(f"{prog}.main").function_handler
        
    logging.basicConfig()
    serve(handler)
