#!/usr/bin/python3

import stat
import os
import atexit
import sys
from datetime import datetime
from collections import defaultdict
import json
import subprocess
import time

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.split(os.path.realpath(__file__))[0]
ROOT_DIR = os.path.split(SCRIPT_DIR)[0] #f"{SCRIPT_DIR}/.."
BUILD_DIR = f"{ROOT_DIR}/build"
BIN_DIR = f"{ROOT_DIR}/bin"
JRUN = f"{BUILD_DIR}/junction/junction_run"
CONFIG = f"{BUILD_DIR}/junction/caladan_test_ts_st.config"
CALADAN_DIR = f"{ROOT_DIR}/lib/caladan"
CHROOT_DIR=f"{ROOT_DIR}/chroot"
RESULT_DIR=f"{ROOT_DIR}/results"
RESULT_LINK=f"{ROOT_DIR}/results/run.recent"

# LINUX_BASELINE = False
USE_CHROOT = True
ENABLE_ELF_BASELINE = True
ENABLE_JIF_USERSPACE_BASELINE = True
DO_KERNEL_EXPS = True
DO_KERNEL_NO_PREFETCH_EXP = True
DO_KERNEL_PREFETCH_EXP = True
DO_KERNEL_PREFETCH_REORDER_EXP = True
REDO_SNAPSHOT = True
DROPCACHE = 4

NEW_VERSION = True

FBENCH = [
    ("node", "hello"),
    ("python", "chameleon"),
    ("python", "float_operation"),
    ("python", "pyaes"),
    ("python", "matmul"),
    ("python", "json_serdes"),
    ("python", "video_processing"),
    ("python", "lr_training"),
    ("python", "image_processing"),
    ("python", "linpack"),
    ("java", "jmatmul"),
]

PATH_TO_FBENCH = f"{ROOT_DIR}/build/junction/samples/snapshots/python/function_bench/"

default_jsons = {
    "hello": '{"test": "Hello, world!"}',
    "chameleon": '{"num_of_rows": 3, "num_of_cols": 4}',
    "float_operation": '{"N": 300}',
    "linpack": '{"N": 300}',
    "matmul": '{"N": 300}',
    "jmatmul": '{"N": 300}',
    "pyaes": '{"length_of_message": 20, "num_of_iterations": 3}',
    "image_processing": '{"path": "' + PATH_TO_FBENCH + 'dataset/image/animal-dog.jpg"}',
    "rnn_serving": '{"language": "Scottish", "start_letters": "ABCDEFGHIJKLMNOP",  "parameter_path": "' + PATH_TO_FBENCH + 'dataset/model/rnn_params.pkl", "model_path": "' + PATH_TO_FBENCH + 'dataset/model/rnn_model.pth"}',
    "json_serdes": '{"json_path": "' + PATH_TO_FBENCH + 'json_serdes/2.json"}',
    "video_processing": '{"input_path": "' + PATH_TO_FBENCH + 'dataset/video/SampleVideo_1280x720_10mb.mp4"}',
    "lr_training": '{"dataset_path": "' + PATH_TO_FBENCH + 'dataset/amzn_fine_food_reviews/reviews10mb.csv"}',
    "cnn_serving": '{"img_path": "' + PATH_TO_FBENCH + 'dataset/image/animal-dog.jpg", "model_path": "' + PATH_TO_FBENCH + 'dataset/model/squeezenet_weights_tf_dim_ordering_tf_kernels.h5"}'
}


RESIZERS = [
    ("java", f"/usr/bin/java -cp {ROOT_DIR}/build/junction/samples/snapshots/java/jar/jna-5.14.0.jar {ROOT_DIR}/build/junction/samples/snapshots/java/resizer/Resizer.java"),
    ("rust", f"{ROOT_DIR}/build/junction/samples/snapshots/rust/resize-rs"),
    ("go", f"{ROOT_DIR}/build/junction/samples/snapshots/go/resizer"),
]

IMAGES = [
    ("large", f"{ROOT_DIR}/build/junction/samples/snapshots/images/IMG_4011.jpg"),
    ("tiny", f"{ROOT_DIR}/build/junction/samples/snapshots/thumbnails/IMG_4011.jpg"),
]

def run(cmd):
    print(cmd)
    sys.stdout.flush()
    subprocess.check_output(cmd, shell=True)

def run_async(cmd):
    print(cmd)
    sys.stdout.flush()
    return subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)

def kill_iok():
    run("sudo pkill iokerneld || true")

def run_iok():
    if os.system("pgrep iok > /dev/null") == 0:
        return
    run(f"sudo {CALADAN_DIR}/scripts/setup_machine.sh nouintr")
    run(f"sudo {CALADAN_DIR}/iokerneld ias nobw noht no_hw_qdel numanode -1 -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel0.log 2>&1 &")
    while os.system("grep -q 'running dataplan' /tmp/iokernel0.log") != 0:
        time.sleep(0.3)
        run("pgrep iokerneld > /dev/null")

def kill_chroot():
    run(f"sudo umount {CHROOT_DIR}/{BIN_DIR}")
    run(f"sudo umount {CHROOT_DIR}/{BUILD_DIR}")
    if jifpager_installed():
        run(f"sudo rm {CHROOT_DIR}/dev/jif_pager")

def setup_chroot():
    if not USE_CHROOT: return
    run(f"sudo mkdir -p {CHROOT_DIR}/{BIN_DIR} {CHROOT_DIR}/{BUILD_DIR}")
    run(f"sudo mount --bind -o ro {BIN_DIR} {CHROOT_DIR}/{BIN_DIR}")
    run(f"sudo mount --bind -o ro {BUILD_DIR} {CHROOT_DIR}/{BUILD_DIR}")

    if jifpager_installed():
        st = os.stat("/dev/jif_pager")
        major = os.major(st.st_rdev)
        minor = os.minor(st.st_rdev)

        run(f"sudo mknod -m 666 {CHROOT_DIR}/dev/jif_pager c {major} {minor} || true")

    atexit.register(kill_chroot)

def jifpager_installed():
    try:
        return DO_KERNEL_EXPS and stat.S_ISCHR(os.stat("/dev/jif_pager").st_mode)
    except:
        return False

def snapshot_elf(cmd, output_image, output_log, extra_flags = "", stop_count = 1, arg = "", name="func"):
    verarg = f"--function_arg '{arg}' --function_name {name}" if NEW_VERSION else f"-S {stop_count}"
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} {verarg} --snapshot-prefix {output_image} -- {cmd} >> {output_log}_snapelf 2>&1")

def snapshot_jif(cmd, output_image, output_log, extra_flags = "", stop_count = 1, arg = "", name="func"):
    verarg = f"--function_arg '{arg}' --function_name {name}" if NEW_VERSION else f"-S {stop_count}"
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} --jif {verarg} --madv_remap --snapshot-prefix {output_image} -- {cmd} >> {output_log}_snapjif 2>&1")

def restore_elf(image, output_log, extra_flags = "", arg="", name="func"):
    verarg = f"--function_arg '{arg}' --function_name {name} " if NEW_VERSION else ""
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} -r {verarg} -- {image}.metadata {image}.elf >> {output_log}_elf 2>&1")

def process_itree(output_image, output_log):
    run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {output_image}.jif {output_image}_itrees.jif build-itrees {CHROOT_DIR if USE_CHROOT else ""} >> {output_log}_builditree 2>&1")

def process_fault_order(output_image, output_log):
    # add ordering to jif
    run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {output_image}_itrees.jif {output_image}_itrees_ord_reorder.jif add-ord --setup-prefetch {output_image}.ord >> {output_log}_addord 2>&1 ")
    run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {output_image}_itrees.jif {output_image}_itrees_ord.jif add-ord {output_image}.ord >> {output_log}_addord 2>&1 ")

def restore_jif(image, output_log, extra_flags = "", arg = "", name="func"):
    verarg = f"--function_arg '{arg}' --function_name {name}" if NEW_VERSION else ""
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} --jif -r {verarg} -- {image}.jm {image}.jif >> {output_log}_jif 2>&1")

def restore_itrees_jif(image, output_log, extra_flags = "", reorder=False, arg = "", name="func"):
    verarg = f"--function_arg '{arg}' --function_name {name}" if NEW_VERSION else ""
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} --jif -r {verarg} -- {image}.jm {image}_itrees{"_ord_reorder" if reorder else ""}.jif >> {output_log}_itrees_jif 2>&1")

def jifpager_restore_itrees(image, output_log, cold=False, minor=False, fault_around=True, measure_latency=False, prefault=False, readahead=True, extra_flags = "", reorder=True, second_app=[], arg = "", name="func"):
    set_fault_around(1 if fault_around else 0)
    set_prefault(1 if prefault else 0)
    set_prefault_minor(1 if minor else 0)
    set_measure_latency(1 if measure_latency else 0)
    set_readahead(1 if readahead else 0)
    jifpager_reset()

    if cold:
        dropcache()

    procs = []
    for sname, sarg, simage in second_app:
        procs.append(run_async(f"sudo -E {JRUN} {CONFIG} {extra_flags} --function_arg '{sarg}' --function_name {sname} --jif -rk -- {simage}.jm {simage}_itrees_ord{"_reorder" if reorder else ""}.jif >> {output_log}_itrees_jif_k_second_app_{sname} 2>&1"))

    for proc in procs:
        proc.wait()
        assert proc.returncode == 0

    jifpager_reset()
    verarg = f"--function_arg '{arg}' --function_name {name}" if NEW_VERSION else ""
    run(f"sudo -E {JRUN} {CONFIG} {extra_flags} {verarg} --jif -rk -- {image}.jm {image}_itrees_ord{"_reorder" if reorder else ""}.jif >> {output_log}_itrees_jif_k  2>&1")

    if second_app: os.system("pkill junction")

    stats = open("/sys/kernel/jif_pager/stats")
    stats = json.loads(stats.readlines()[0])
    print(dict(stats))

    total_pages = stats["sync_pages_read"] + stats["async_pages_read"]
    total_faults = stats["minor_faults"] + stats["major_faults"] + stats["pre_minor_faults"] + stats["pre_major_faults"]

    if total_pages > 0:
        overread = float(total_faults / total_pages) * 100.0
        batch_size = total_pages / stats["sync_readaheads"]

        stats["percent_touched"] = overread
        stats["batch_size"] = batch_size

    stats["readahead"] = readahead
    stats["prefault"] = prefault
    stats["cold"] = cold

    key = image.split("/")[-1]
    stats['key'] = key
    with open(f"{output_log}_itrees_jif_k_kstats", "a") as f:
        f.write(json.dumps(stats))
        f.write('\n')

def set_readahead(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/readahead")

def set_fault_around(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/fault_around")

def set_prefault(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/prefault")

def set_prefault_minor(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/prefault_minor")

def set_measure_latency(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/measure_latency")

def jifpager_reset():
    run("echo 1 | sudo tee /sys/kernel/jif_pager/reset")

def generate_images(cmd, output_image, logname, stop_count = 1, extra_flags = "", name="", arg=""):
    if ENABLE_ELF_BASELINE:
        snapshot_elf(cmd, output_image, logname, extra_flags, stop_count=stop_count, name=name, arg=arg)
    snapshot_jif(cmd, output_image, logname, extra_flags, stop_count=stop_count, name=name, arg=arg)
    process_itree(f"{CHROOT_DIR}/{output_image}" if USE_CHROOT else output_image, logname)

    # generate ord with tracer
    restore_jif(output_image, f"{logname}_buildord", extra_flags=f" {extra_flags} --stackswitch --mem-trace --mem-trace-out {output_image}.ord", name=name, arg=arg)

    process_fault_order(f"{CHROOT_DIR}/{output_image}" if USE_CHROOT else output_image, logname)

def get_baseline(cmd, edir):
    run(f"DONTSTOP=1 {cmd} >> {edir}/restore_images_linux 2>&1")

def dropcache():
    for i in range(DROPCACHE):
        if i > 0: time.sleep(10)
        run("echo 3 | sudo tee /proc/sys/vm/drop_caches")

RESTORE_CONFIG_SET = [
    ("linux", "Linux warm"),
    ("elf", "ELF"),
    ("itrees_jif", "JIF\nuserspace"),
    ("itrees_jif_k", "JIF\nkernel"),
    ("sa_itrees_jif_k", "JIF k\nFunction bench\npreviously run"),
    ("self_itrees_jif_k", "JIF k\nThis function\npreviously run"),
    ("prefault_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)"),
    ("prefault_minor_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\nprefault minor"),
    ("prefault_reorder_itrees_jif_k", "JIF\nkernel\nprefetch)\n(w/ reorder)"),
    ("prefault_reorder_minor_itrees_jif_k", "JIF k\nFully cold + \nall optimizations"),
    ("prefault_reorder_minor_sa_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\nprefault minor\nsa"),
    ("reorder_itrees_jif_k", "JIF\nkernel\nReorder"),
    ("reorder_sa_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\nsa"),

    # Not commonly used ones
    ("reorder_itrees_jif", "JIF\nuserspace\nReordered"),
    ("nora_itrees_jif_k", "JIF\nkernel\nNo RA"),
    ("nora_reorder_itrees_jif_k", "JIF\nkernel\nNo RA\nReorder"),
    ("nora_prefault_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\nNo RA"),
    ("prefault_reorder_simple_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\n(float op)"),
    ("prefault_reorder_self_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\n(self)"),
    ("reorder_simple_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\n(float op)"),
    ("reorder_self_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\n(self)"),
    ("nora_prefault_reorder_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\nNoRA"),
]

def restore_image(image, logname, extra_flags="", name="", arg="", second_app=[]):
    if ENABLE_ELF_BASELINE:
        dropcache()
        restore_elf(image, logname, extra_flags, name=name, arg=arg)
    if ENABLE_JIF_USERSPACE_BASELINE:
        dropcache()
        restore_itrees_jif(image, logname, extra_flags, name=name, arg=arg)

    # use the reorder file with userspace restore (increases VMA setup costs)
    if False:
        dropcache()
        restore_itrees_jif(image, f"{logname}_reorder", extra_flags, reorder=True, name=name, arg=arg)

    if jifpager_installed():
        if DO_KERNEL_NO_PREFETCH_EXP:
            # Kernel module restore (no prefetching)
            jifpager_restore_itrees(image, logname, extra_flags=extra_flags, prefault=False, cold=True, reorder=False, name=name, arg=arg)

            # Kernel module restore using reorder file, with/without readahead
            if False:
                jifpager_restore_itrees(image, f"{logname}_reorder", extra_flags=extra_flags, prefault=False, cold=True, reorder=True, name=name, arg=arg)
                jifpager_restore_itrees(image, f"{logname}_nora", extra_flags=extra_flags, prefault=False, cold=True, reorder=False, name=name, arg=arg)
                jifpager_restore_itrees(image, f"{logname}_nora_reorder", extra_flags=extra_flags, prefault=False, cold=True, reorder=True, name=name, arg=arg)

        if DO_KERNEL_PREFETCH_EXP:
            # Prefault pages
            jifpager_restore_itrees(image, f"{logname}_prefault", extra_flags=extra_flags, prefault=True, cold=True, reorder=False, name=name, arg=arg)
            # jifpager_restore_itrees(image, f"{logname}_prefault_minor", extra_flags=extra_flags, minor=True, prefault=True, cold=True, reorder=False, name=name, arg=arg)
        if DO_KERNEL_PREFETCH_REORDER_EXP:
            # Prefault pages with reordered contiguous data section
            # jifpager_restore_itrees(image, f"{logname}_prefault_reorder", extra_flags=extra_flags, prefault=True, cold=True, reorder=True, name=name, arg=arg)
            jifpager_restore_itrees(image, f"{logname}_prefault_reorder_minor", extra_flags=extra_flags, minor=True, prefault=True, cold=True, reorder=True, name=name, arg=arg)

        if False:
            # try warming things with one image restore before the main one
            for tag, f in [("simple", "/tmp/float_operation"), ("self", name)]:
                jifpager_restore_itrees(image, f"{logname}_prefault_reorder_{tag}", extra_flags=extra_flags, prefault=True, cold=True, reorder=True, second_app=f, name=name, arg=arg)
                jifpager_restore_itrees(image, f"{logname}_reorder_{tag}", extra_flags=extra_flags, prefault=False, cold=True, reorder=True, second_app=f, name=name, arg=arg)

        if second_app:
            jifpager_restore_itrees(image, f"{logname}_sa", extra_flags=extra_flags, minor=False, prefault=False, cold=True, reorder=False, name=name, arg=arg, second_app=second_app)
        # # jifpager_restore_itrees(image, f"{logname}", extra_flags=extra_flags, minor=False, prefault=False, cold=True, reorder=True, name=name, arg=arg, second_app=second_app)

        # jifpager_restore_itrees(image, f"{logname}_self", extra_flags=extra_flags, minor=False, prefault=False, cold=True, reorder=False, name=name, arg=arg, second_app=second_app)
        second_app = [(name, arg, image)]
        jifpager_restore_itrees(image, f"{logname}_self", extra_flags=extra_flags, minor=False, prefault=False, cold=True, reorder=False, name=name, arg=arg, second_app=second_app)


def get_cmd(lang, fn):
    if lang == "python":
        script = "new_runner.py" if NEW_VERSION else "run.py"
        return f"{ROOT_DIR}/bin/venv/bin/python3 " + f"{ROOT_DIR}/build/junction/samples/snapshots/python/function_bench/" + f"{script} {fn}"

    if lang == "node":
        return f"/usr/bin/node --jitless --expose-gc " + f"{ROOT_DIR}/build/junction/samples/snapshots/node/" + f"function_bench/run.js {fn}"

    if lang == "java":
        if fn == "jmatmul":
            return f"/usr/bin/java -cp {ROOT_DIR}/build/junction/samples/snapshots/java/jar/jna-5.14.0.jar:{ROOT_DIR}/build/junction/samples/snapshots/java/jar/json-simple-1.1.1.jar {ROOT_DIR}/build/junction/samples/snapshots/java/matmul/MatMul.java --new_version"

        assert False, f"unknown function for java `{fn}`, only know matmul"

    assert False, f"unknown lang for cmd `{lang}`: can only map python, node and java"

def get_fbench_times(edir):
    eflags = ""
    if USE_CHROOT:
        eflags += f" --chroot={CHROOT_DIR}  --cache_linux_fs "
    if REDO_SNAPSHOT:
        for lang, fn in FBENCH:
            stop_count = 2 if "java" in lang else 1
            cmd = get_cmd(lang, fn)
            generate_images(cmd, f"/tmp/{fn}", f"{edir}/generate_images", stop_count=stop_count, extra_flags=eflags, name=fn, arg=default_jsons[fn])
        for name, cmd in RESIZERS:
            stop_count = 2 if "java" in name else 1
            for image, path in IMAGES:
                fullcmd = f"{cmd} --new_version" if name != "rust" else f"{cmd} --new-version"
                nm = f"{name}_resizer_{image}"
                generate_images(fullcmd, f"/tmp/{nm}", f"{edir}/generate_images", stop_count=stop_count, extra_flags=eflags, name=nm, arg=path)

    for lang, fn in FBENCH:
        cmd = get_cmd(lang, fn)
        second_app = []
        for lang2, fn2 in FBENCH:
            if fn == fn2 or lang2 != lang:
                continue
            second_app.append((fn2, default_jsons[fn2], f"/tmp/{fn2}"))

        restore_image(f"/tmp/{fn}", f"{edir}/restore_images", extra_flags=eflags, name=fn, arg=default_jsons[fn], second_app=second_app)

    for name, cmd in RESIZERS:
        for image, path in IMAGES:
            nm = f"{name}_resizer_{image}"

            second_app = []
            for simage, spath in IMAGES:
                if simage == image:
                    continue
                nm2 = f"{name}_resizer_{simage}"
                second_app.append((nm2, spath, f"/tmp/{nm2}"))

            restore_image(f"/tmp/{nm}", f"{edir}/restore_images", extra_flags=eflags, name=nm, arg=path, second_app=second_app)


def get_one_log(name):
    try:
        with open(name) as x:
            dat = x.read().splitlines()
    except:
        return {}

    progs = {}
    prev_restore = None
    for l in dat:
        if "DATA  " not in l:
            if "restore time" in l:
                prev_restore = l
            continue
        lx = l.split("DATA  ")[-1].strip()
        xx = json.loads(lx)
        assert xx['program'] not in progs, f"{name}: {xx['program']} already in {progs}"

        if prev_restore:
            l = prev_restore.split("restore time")[1].split()
            xx["metadata_restore"] = int(l[2])
            xx["data_restore"] = int(l[4])
            xx["fs_restore"] = int(l[6])
            prev_restore = None

        progs[xx["program"]] = xx

    return progs

def getstats_old(d):
    return {
        'cold_first_iter': d["cold"][0],
        'data_restore': d.get("data_restore"),
        'first_iter': d['warmup'][0],
        'warm_iter': d['warmup'][-1],
        'metadata_restore': d.get("metadata_restore"),
        'fs_restore': d.get("fs_restore"),
    }

def getstats(d):
    return {
        'cold_first_iter': d.get("first_iter"),
        'data_restore': d.get("data_restore"),
        # 'first_iter': d['warmup'][0],
        'warm_iter': d['times'][2],
        'metadata_restore': d.get("metadata_restore"),
        'fs_restore': d.get("fs_restore"),
    }

def get_kstats(fn, data, expn):
    try:
        with open(fn, "r") as f:
            for line in f.readlines():
                jx = json.loads(line)
                data[jx['key']][expn]['jifpager_stats_ns'] = jx
    except:
        pass

def parse_fbench_times(edir):
    from pprint import pprint

    out = defaultdict(dict)

    for tag, name in RESTORE_CONFIG_SET:
        for prog, d in get_one_log(f"{edir}/restore_images_{tag}").items():
            if NEW_VERSION:
                out[prog][tag] = getstats(d)
            else:
                out[prog][tag] = getstats_old(d)
        get_kstats(f"{edir}/restore_images_{tag}_kstats", out, tag)

    pprint(out)
    return out

def plot_workloads(edir, data):
    workloads = list(data.keys())
    num_workloads = len(workloads)
    fig, axes = plt.subplots(num_workloads, 1, figsize=(10, 5 * num_workloads))

    if num_workloads == 1:
        axes = [axes]

    def get_colors(cat):
        return {
            'function': 'tab:blue',
            'metadata': 'tab:orange',
            'fs': 'tab:green',
            'data': 'tab:red',
            'slowdown': 'tab:blue',
        }.get(cat)

    for ax, workload in zip(axes, workloads):
        categories = data[workload]

        # jifpager_stats_ns = categories['jifpager_stats_ns']

        # how do I get needed throughput? in pages/s
        # for x in jifpager_stats_ns:
        #     print(x)
        # if not jifpager_stats_ns.get("readahead", False):
        #     no_readahead = jifpager_stats_ns

        # should only be major faults but just in case
        # total_pages = no_readahead["major_faults"] + no_readahead["minor_faults"]
        # read_latency = no_readahead["average_sync_read_latency"]

        # ideal_throughput = int((total_pages / first_iter) * 1000000 * 4096)
        # bytes per nanosecond
        # actual_throughput = int((4096 / read_latency) * 1000000000)

        # print(f"{workload} ideal throughput = {ideal_throughput / 1024 ** 2}MB/s")
        # print(f"{workload} actual throughput = {actual_throughput / 1024 ** 2}MB/s")

        WARM_ITER = list(categories.items())[0][1]["warm_iter"]
        stack1 = [
            (WARM_ITER, 'function')
        ]

        SLOWDOWN = False
        FUNCTION_ONLY = False
        SUM = False
        stacks = []
        if not SLOWDOWN:
            stacks.append((stack1, "Warm", None))

        for exp, ename in RESTORE_CONFIG_SET:
            if exp not in categories:
                continue
            jpstats = None
            if 'jifpager_stats_ns' in categories[exp]:
                jpstats = categories[exp]['jifpager_stats_ns']
            stacks.append(([
                (categories[exp]["cold_first_iter"], "function"),
                (categories[exp]["metadata_restore"], "metadata"),
                (categories[exp]["fs_restore"], "fs"),
                (categories[exp]["data_restore"], "data"),
            ], ename, jpstats))

        seen = set()

        def get_lbl(label):
            if label in seen: return None
            seen.add(label)
            return {
                'function': 'Function',
                'metadata': 'Cereal restore',
                'fs': 'MemFS restore',
                'data': 'VMA restore'
            }.get(label, label)

        for stack, label, jpstat in stacks:
            bottom = 0
            if SUM or SLOWDOWN:
                if FUNCTION_ONLY:
                    sm = next(l[0] for l in stack if l[1] == "function")
                else:
                    sm = sum(l[0] for l in stack if l[0] is not None) #- WARM_ITER
                if SLOWDOWN:
                    sm /= WARM_ITER
                ax.bar(label, sm, color=get_colors('slowdown'))
            else:
                for val, category in stack:
                    if val is None:
                        continue
                    ax.bar(label, val, bottom=bottom, color=get_colors(category), label=get_lbl(category))
                    bottom += val
            if jpstat is None:
                continue
            txt = f"Major: {jpstat['major_faults']}"
            # txt += f"\n  Pre-major: {jpstat['pre_major_faults']}"
            txt += f"\n Minor: {jpstat['minor_faults']}"
            # txt += f"\n  Pre-minor: {jpstat['pre_minor_faults']}"
            ax.text(
                x=label,
                y=sm / 2 if SLOWDOWN or SUM else stack[0][0] / 2,
                s=txt,
                ha='center',
                va='center',
                color='white',
                fontsize=8,
                fontweight='bold'
            )

        ax.set_ylabel("Microseconds" if not SLOWDOWN else "Slowdown")
        # ax.set_yscale('log')
        # ax.set_ylim(1, 5e5)
        if workload in FBENCH:
            workload = "function_bench: " + workload
        if SLOWDOWN:
            workload += f" - {WARM_ITER / 1000} ms warm iter"
        ax.set_title(workload)
        ax.legend()

    plt.tight_layout()
    plt.savefig(f'{edir}/graph.pdf', bbox_inches='tight')

def main():
    edir = f"{RESULT_DIR}/run.{datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}"
    os.system(f"mkdir -p {edir}")
    os.system(f"ln -sfn {edir} {RESULT_LINK}")
    get_fbench_times(edir)
    data = parse_fbench_times(edir)
    plot_workloads(edir, data)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        for d in sys.argv[1:]:
            plot_workloads(d, parse_fbench_times(d))
    else:
        run_iok()
        setup_chroot()
        main()
