import socket

def patch_socket():
    def noop_setsockopt(self, level, optname, value):
        pass

    socket.socket.setsockopt = noop_setsockopt
