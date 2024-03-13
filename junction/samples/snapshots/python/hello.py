import sys
import os, signal

if __name__ == "__main__":
    print("Hello world!")

    # flush to make sure the stuff from above isn't printed when we are restored
    sys.stdout.flush()

    # wait for snapshot
    os.kill(os.getpid(), signal.SIGSTOP)

    print("restored")
