import importlib
import sys
import json
import ctypes
import gc

libc = ctypes.CDLL(None)

prog = sys.argv[1]

if prog == "chameleon" or prog == "pyaes":
    prog += "1"

# chameleon and pyaes are already py libraries; use modules from the directories instead
main = importlib.import_module(f"{prog}.main")

def snapshot_prepare():
    sys.stdout.flush()
    for i in range(3):
        gc.collect()
    libc.malloc_trim(0)

with open("/serverless/chan0", "r+") as f:
    while True:
        cmd = f.readline().strip()
        if cmd == "SNAPSHOT_PREPARE":
            snapshot_prepare()
            f.write("OK")
            continue
        json_req = json.loads(cmd)
        ret = main.function_handler(json_req)
        f.write(str(main.function_handler(json_req)))


