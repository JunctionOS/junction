import sys

import grpc
import helloworld_pb2
import helloworld_pb2_grpc

def run(ip):
    while True:
        with grpc.insecure_channel(f'{ip}:50051') as channel:
            stub = helloworld_pb2_grpc.GreeterStub(channel)
            request = helloworld_pb2.HelloRequest(name="record")
            response = stub.SayHello(request)

        print(f"got response: {response.message}")
        if response.message == "OK":
            return

if __name__ == '__main__':
    run(str(sys.argv[1]))
