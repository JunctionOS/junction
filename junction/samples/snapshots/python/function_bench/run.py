import importlib
import sys
import json
import os
import signal
import time
import ctypes
import gc

libc = ctypes.CDLL(None)
syscall = libc.syscall

PATH_TO_FBENCH = str(os.path.dirname(os.path.realpath(__file__))) + "/"

default_jsons = {
    "chameleon": '{"num_of_rows": 3, "num_of_cols": 4}',
    "float_operation": '{"N": 300}',
    "linpack": '{"N": 300}',
    "matmul": '{"N": 300}',
    "pyaes": '{"length_of_message": 20, "num_of_iterations": 3}',
    "image_processing": '{"path": "' + PATH_TO_FBENCH + 'dataset/image/animal-dog.jpg"}',
    "rnn_serving": '{"language": "Scottish", "start_letters": "ABCDEFGHIJKLMNOP",  "parameter_path": "' + PATH_TO_FBENCH + 'dataset/model/rnn_params.pkl", "model_path": "' + PATH_TO_FBENCH + 'dataset/model/rnn_model.pth"}',
    "json_serdes": '{"json_path": "' + PATH_TO_FBENCH + 'json_serdes/2.json"}',
    "video_processing": '{"input_path": "' + 'dataset/video/SampleVideo_1280x720_10mb.mp4"}',
    "lr_training": '{"dataset_path": "' + PATH_TO_FBENCH + 'dataset/amzn_fine_food_reviews/reviews10mb.csv"}',
    "cnn_serving": '{"img_path": "' + PATH_TO_FBENCH + 'dataset/image/animal-dog.jpg", "model_path": "' + PATH_TO_FBENCH + 'dataset/model/squeezenet_weights_tf_dim_ordering_tf_kernels.h5"}'
}

if len(sys.argv) < 2:
    print("usage: run.py <program-name> <optional: json>")
    exit()

prog = sys.argv[1]

if prog not in default_jsons:
    print(f"error: {prog} not in {default_jsons.keys()}")
    exit()

json_string = default_jsons[prog]
if len(sys.argv) == 3:
    json_string = sys.argv[2]

json_req = json.loads(json_string)

# chameleon and pyaes are already py libraries; use modules from the directories instead
if prog == "chameleon" or prog == "pyaes":
    prog += "1"

main = importlib.import_module(f"{prog}.main")
print("starting")
sys.stdout.flush()

# warmup iters
warmups =[]
for i in range(10):
    start = time.perf_counter_ns()
    print(f" iter {i} {main.function_handler(json_req)}")
    end = time.perf_counter_ns()
    warmups.append((end - start) / 1000.0)

print(f"stopping. one warm iteration takes {warmups[-1]} us)")
sys.stdout.flush()
for i in range(3):
    gc.collect()
libc.malloc_trim(0)

# stop for snapshot
os.kill(os.getpid(), signal.SIGSTOP)

cold = []
for i in range(3):
    start = time.perf_counter_ns()
    print(main.function_handler(json_req))
    end = time.perf_counter_ns()
    cold.append((end - start) / 1000.0)

print(f"done. one cold iteration takes {cold[0]} us)")
print("DATA ", json.dumps({"warmup": warmups, 'cold': cold, 'program': sys.argv[1]}))

sys.stdout.flush()
syscall(231, 0)


