#!/usr/bin/python3

import matplotlib.pyplot as plt
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

mpl.use("Agg")

SCRIPT_DIR = os.path.split(os.path.realpath(__file__))[0]
ROOT_DIR = os.path.split(SCRIPT_DIR)[0]
BUILD_DIR = f"{ROOT_DIR}/build"
BIN_DIR = f"{ROOT_DIR}/bin"
JRUN = f"{BUILD_DIR}/junction/junction_run"
CONFIG = f"{BUILD_DIR}/junction/caladan_test_ts_st.config"
CALADAN_DIR = f"{ROOT_DIR}/lib/caladan"
CHROOT_DIR = f"{ROOT_DIR}/chroot"
RESULT_DIR = f"{ROOT_DIR}/results"
RESULT_LINK = f"{ROOT_DIR}/results/run.recent"

PATH_TO_FBENCH = f"{ROOT_DIR}/build/junction/samples/snapshots/python/function_bench/"

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

RESTORE_CONFIG_SET = [
    ("linux", "Linux warm"),
    ("elf", "ELF"),
    ("itrees_jif", "JIF\nuserspace"),
    ("itrees_jif_k", "JIF\nkernel"),
    ("sa_itrees_jif_k", "JIF k\nFunction bench\npreviously run"),
    ("self_itrees_jif_k", "JIF k\nThis function\npreviously run"),
    ("prefault_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)"),
    ("prefault_minor_itrees_jif_k",
     "JIF\nkernel\n(w/ prefetch)\nprefault minor"),
    ("prefault_reorder_itrees_jif_k", "JIF\nkernel\nprefetch)\n(w/ reorder)"),
    ("prefault_reorder_minor_itrees_jif_k",
     "JIF k\nFully cold + \nall optimizations"),
    ("prefault_reorder_minor_sa_itrees_jif_k",
     "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\nprefault minor\nsa"),
    ("reorder_itrees_jif_k", "JIF\nkernel\nReorder"),
    ("reorder_sa_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\nsa"),

    # Not commonly used ones
    ("reorder_itrees_jif", "JIF\nuserspace\nReordered"),
    ("nora_itrees_jif_k", "JIF\nkernel\nNo RA"),
    ("nora_reorder_itrees_jif_k", "JIF\nkernel\nNo RA\nReorder"),
    ("nora_prefault_itrees_jif_k", "JIF\nkernel\n(w/ prefetch)\nNo RA"),
    ("prefault_reorder_simple_itrees_jif_k",
     "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\n(float op)"),
    ("prefault_reorder_self_itrees_jif_k",
     "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\n(self)"),
    ("reorder_simple_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\n(float op)"),
    ("reorder_self_itrees_jif_k", "JIF\nkernel\n(w/ reorder)\n(self)"),
    ("nora_prefault_reorder_itrees_jif_k",
     "JIF\nkernel\n(w/ prefetch)\n(w/ reorder)\nNoRA"),
]

# util functions


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
    run(f"sudo {CALADAN_DIR}/iokerneld ias nobw noht no_hw_qdel numanode -1 -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel0.log 2>&1 &"
        )
    while os.system("grep -q 'running dataplan' /tmp/iokernel0.log") != 0:
        time.sleep(0.3)
        run("pgrep iokerneld > /dev/null")


def kill_chroot():
    run(f"sudo umount {CHROOT_DIR}/{BIN_DIR}")
    run(f"sudo umount {CHROOT_DIR}/{BUILD_DIR}")
    if jifpager_installed():
        run(f"sudo rm {CHROOT_DIR}/dev/jif_pager")


def setup_chroot():
    if not USE_CHROOT:
        return
    run(f"sudo mkdir -p {CHROOT_DIR}/{BIN_DIR} {CHROOT_DIR}/{BUILD_DIR}")
    run(f"sudo mount --bind -o ro {BIN_DIR} {CHROOT_DIR}/{BIN_DIR}")
    run(f"sudo mount --bind -o ro {BUILD_DIR} {CHROOT_DIR}/{BUILD_DIR}")

    if jifpager_installed():
        st = os.stat("/dev/jif_pager")
        major = os.major(st.st_rdev)
        minor = os.minor(st.st_rdev)

        run(f"sudo mknod -m 666 {CHROOT_DIR}/dev/jif_pager c {major} {minor} || true"
            )

    atexit.register(kill_chroot)


def jifpager_installed():
    try:
        return DO_KERNEL_EXPS and stat.S_ISCHR(
            os.stat("/dev/jif_pager").st_mode)
    except BaseException:
        return False


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


def dropcache():
    for i in range(DROPCACHE):
        if i > 0:
            time.sleep(10)
        run("echo 3 | sudo tee /proc/sys/vm/drop_caches")


def prefix_fbench(fname: str):
    return PATH_TO_FBENCH + fname


# Test definitions


class Test:

    @classmethod
    def template(cls, lang: str, name: str, cmd: str, arg_map):
        """
        punch out a template of tests, where the arg_map is a map from arg_name -> arg
        return a list of Tests
        """
        return [
            cls(lang, name, cmd, args, arg_name)
            for arg_name, args in arg_map.items()
        ]

    def __init__(self,
                 lang: str,
                 name: str,
                 cmd: str,
                 args: str,
                 arg_name: str = ""):
        self.lang = lang
        self.name = name
        self.cmd = cmd
        self.args = args
        self.stop_count = 2 if lang == 'java' else 1
        self.arg_name = arg_name

    def id(self):
        if self.arg_name:
            return f"{self.lang}_{self.name}_{self.arg_name}"
        else:
            return f"{self.lang}_{self.name}"

    def baseline(self, result_dir: str):
        run(f"DONTSTOP=1 {self.cmd} >> {result_dir}/restore_images_linux 2>&1")

    def snapshot_prefix(self):
        func_id = self.id()
        return f"/tmp/{func_id}"

    def snapshot_elf(self, output_log: str):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}" if NEW_VERSION else f"-S {self.stop_count()}"
        chroot_args = f" --chroot={CHROOT_DIR} --cache_linux_fs" if USE_CHROOT else ""
        prefix = self.snapshot_prefix()

        run(f"sudo -E {JRUN} {CONFIG} {junction_args} {chroot_args} --snapshot-prefix {prefix} -- {self.cmd} >> {output_log}_snap_elf 2>&1"
            )

    def snapshot_jif(self, output_log: str):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}" if NEW_VERSION else f"-S {self.stop_count()}"
        chroot_args = f" --chroot={CHROOT_DIR} --cache_linux_fs" if USE_CHROOT else ""
        prefix = self.snapshot_prefix()

        run(f"sudo -E {JRUN} {CONFIG} {junction_args} {chroot_args} --jif --madv_remap --snapshot-prefix {prefix} -- {self.cmd} >> {output_log}_snap_jif 2>&1"
            )

    def process_itree(self, output_log: str):
        prefix = CHROOT_DIR + '/' + self.snapshot_prefix(
        ) if USE_CHROOT else self.snapshot_prefix()

        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}.jif {prefix}_itrees.jif build-itrees {CHROOT_DIR if USE_CHROOT else ''} >> {output_log}_build_itree 2>&1"
            )

    def process_fault_order(self, output_log: str):
        '''add ordering to the jif'''
        prefix = CHROOT_DIR + '/' + self.snapshot_prefix(
        ) if USE_CHROOT else self.snapshot_prefix()

        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}_itrees.jif {prefix}_itrees_ord_reorder.jif add-ord --setup-prefetch {prefix}.ord >> {output_log}_add_ord_reord 2>&1 "
            )
        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}_itrees.jif {prefix}_itrees_ord.jif add-ord {prefix}.ord >> {output_log}_add_ord 2>&1 "
            )

    def restore_elf(self, output_log: str):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}" if NEW_VERSION else ""
        chroot_args = f" --chroot={CHROOT_DIR} --cache_linux_fs" if USE_CHROOT else ""
        prefix = self.snapshot_prefix()

        run(f"sudo -E {JRUN} {CONFIG} -r {junction_args} {chroot_args} -- {prefix}.metadata {prefix}.elf >> {output_log}_elf 2>&1"
            )

    def userspace_restore_jif(self,
                              output_log: str,
                              trace: bool = False,
                              itrees: bool = False,
                              reorder: bool = False):

        def construct_jif_fname(self, itrees: bool, reorder: bool) -> str:
            fname = self.snapshot_prefix()
            if itrees:
                fname += '_itrees'
            if reorder:
                fname += '_ord_reorder'
            fname += '.jif'
            return fname

        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}" if NEW_VERSION else ""
        chroot_args = f" --chroot={CHROOT_DIR} --cache_linux_fs" if USE_CHROOT else ""
        prefix = self.snapshot_prefix()
        mem_flags = f"--stackswitch --mem-trace --mem-trace-out {prefix}.ord" if trace else ""

        jif_fname = construct_jif_fname(self, itrees, reorder)

        run(f"sudo -E {JRUN} {CONFIG} {junction_args} {mem_flags} {chroot_args} --jif -r -- {prefix}.jm {jif_fname} >> {output_log}_jif 2>&1"
            )

    def jifpager_restore_jif(self,
                             output_log: str,
                             prefault: bool = False,
                             cold: bool = False,
                             minor: bool = False,
                             fault_around: bool = True,
                             measure_latency: bool = False,
                             readahead: bool = True,
                             reorder: bool = True,
                             second_apps=[]):
        set_fault_around(1 if fault_around else 0)
        set_prefault(1 if prefault else 0)
        set_prefault_minor(1 if minor else 0)
        set_measure_latency(1 if measure_latency else 0)
        set_readahead(1 if readahead else 0)
        jifpager_reset()

        if cold:
            dropcache()

        suffix = "_reorder" if reorder else ""
        chroot_args = f" --chroot={CHROOT_DIR} --cache_linux_fs" if USE_CHROOT else ""

        procs = []
        for idx, sapp in enumerate(second_apps):
            config = f"/tmp/beconf_{idx}.conf"
            ip = f"123.45.6.{idx}"
            run(f"sed 's/host_addr.*/host_addr {ip}/' {CONFIG} > {config}")
            junction_args = f"--function_arg '{sapp.args}' --function_name {sapp.id()}"
            prefix = sapp.snapshot_prefix()
            procs.append(
                run_async(
                    f"sudo -E {JRUN} {config} {chroot_args} {junction_args} --jif -rk -- {prefix}.jm {prefix}_itrees_ord{suffix}.jif >> {output_log}_itrees_jif_k_second_app_{sapp.id()} 2>&1"
                ))

        for proc, app in zip(procs, second_apps):
            proc.wait()
            assert proc.returncode == 0, f"failed to run function: {app.id()}"

        jifpager_reset()
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}"
        prefix = self.snapshot_prefix()
        run(f"sudo -E {JRUN} {CONFIG} {chroot_args} {junction_args} --jif -rk -- {prefix}.jm {prefix}_itrees_ord{suffix}.jif >> {output_log}_itrees_jif_k  2>&1"
            )

        stats = open("/sys/kernel/jif_pager/stats")
        stats = json.loads(stats.readlines()[0])
        print(dict(stats))

        total_pages = stats["sync_pages_read"] + stats["async_pages_read"]
        total_faults = stats["minor_faults"] + stats["major_faults"] + \
            stats["pre_minor_faults"] + stats["pre_major_faults"]

        if total_pages > 0:
            overread = float(total_faults / total_pages) * 100.0
            batch_size = total_pages / stats["sync_readaheads"]

            stats["percent_touched"] = overread
            stats["batch_size"] = batch_size

        stats["readahead"] = readahead
        stats["prefault"] = prefault
        stats["cold"] = cold
        stats['key'] = self.id()
        with open(f"{output_log}_itrees_jif_k_kstats", "a") as f:
            f.write(json.dumps(stats))
            f.write('\n')

    def generate_images(self, output_log: str):
        if ENABLE_ELF_BASELINE:
            self.snapshot_elf(output_log)

        self.snapshot_jif(output_log)
        self.process_itree(output_log)

        # generate ord
        self.userspace_restore_jif(f"{output_log}_build_ord", trace=True)
        self.process_fault_order(output_log)

    def restore_image(self, output_log: str, second_apps=[]):
        if ENABLE_ELF_BASELINE:
            dropcache()
            self.restore_elf(output_log)

        if ENABLE_JIF_USERSPACE_BASELINE:
            dropcache()
            self.userspace_restore_jif(output_log, itrees=True)

        # use the reorder file with userspace restore (increases VMA setup
        # costs)
        if False:
            dropcache()
            self.userspace_restore_jif(f"{output_log}_reorder",
                                       reorder=True,
                                       itrees=True)

        if jifpager_installed():
            if DO_KERNEL_NO_PREFETCH_EXP:
                # Kernel module restore (no prefetching)
                self.jifpager_restore_jif(output_log,
                                          prefault=False,
                                          cold=True,
                                          reorder=True)

                # Kernel module restore using reorder file, with/without
                # readahead
                if False:
                    self.jifpager_restore_jif(f"{output_log}_reorder",
                                              prefault=False,
                                              cold=True,
                                              reorder=True)
                    self.jifpager_restore_jif(f"{output_log}_nora",
                                              prefault=False,
                                              cold=True,
                                              reorder=False)
                    self.jifpager_restore_jif(f"{output_log}_nora_reorder",
                                              prefault=False,
                                              cold=True,
                                              reorder=True)

            if DO_KERNEL_PREFETCH_EXP:
                # Prefault pages
                self.jifpager_restore_jif(f"{output_log}_prefault",
                                          prefault=True,
                                          cold=True,
                                          reorder=False)
                # self.jifpager_restore_jif(f"{output_log}_prefault_minor,
                # minor=True, prefault=True, cold=True, reorder=False)

            if DO_KERNEL_PREFETCH_REORDER_EXP:
                # Prefault pages with reordered contiguous data section
                # self.jifpager_restore_jif(f"{output_log}_prefault_reorder,
                # prefault=True, cold=True, reorder=True)
                self.jifpager_restore_jif(
                    f"{output_log}_prefault_reorder_minor",
                    minor=True,
                    prefault=True,
                    cold=True,
                    reorder=True)

            if False:
                for tag, function in [("simple", FLOAT_OPERATION),
                                      ("self", self)]:
                    self.jifpager_restore_jif(
                        f"{output_log}_prefault_reorder_{tag}",
                        prefault=True,
                        cold=True,
                        reorder=True,
                        second_apps=[function])
                    self.jifpager_restore_jif(f"{output_log}_reorder_{tag}",
                                              prefault=False,
                                              cold=True,
                                              reorder=True,
                                              second_apps=[function])

            if second_apps:
                self.jifpager_restore_jif(f"{output_log}_sa",
                                          minor=False,
                                          prefault=False,
                                          cold=False,
                                          reorder=False,
                                          second_apps=second_apps)

            # self.jifpager_restore_jif(output_log, minor=False, prefault=False, cold=True, reorder=True, second_apps=second_apps)
            # self.jifpager_restore_jif(f"{output_log}_self", minor=False, prefault=False, cold=True, reorder=False, second_apps=second_apps)

            self.jifpager_restore_jif(f"{output_log}_self",
                                      minor=False,
                                      prefault=False,
                                      cold=True,
                                      reorder=False,
                                      second_apps=[self])


class PyFBenchTest(Test):

    def __init__(self, name: str, args: str, arg_name: str = ""):
        script = "new_runner.py" if NEW_VERSION else "run.py"
        super().__init__(
            'python', name,
            f"{ROOT_DIR}/bin/venv/bin/python3 {ROOT_DIR}/build/junction/samples/snapshots/python/function_bench/{script} {name}",
            args, arg_name)


class NodeFBenchTest(Test):

    def __init__(self, name: str, args: str, arg_name: str = ""):
        super().__init__(
            'node', name,
            f"/usr/bin/node --jitless --expose-gc {ROOT_DIR}/build/junction/samples/snapshots/node/function_bench/run.js {name}",
            args, arg_name)


class ResizerTest(Test):

    @classmethod
    def template(cls, lang: str, cmd: str, arg_map):
        """
        punch out a template of tests, where the arg_map is a map from arg_name -> arg
        return a list of Tests
        """
        return [
            cls(lang, cmd, args, arg_name)
            for arg_name, args in arg_map.items()
        ]

    def __init__(self, lang: str, cmd: str, args: str, arg_name: str):
        super().__init__(lang, 'resizer', cmd, args, arg_name)


RESIZER_IMAGES = {
    "large":
    f"{ROOT_DIR}/build/junction/samples/snapshots/images/IMG_4011.jpg",
    "tiny":
    f"{ROOT_DIR}/build/junction/samples/snapshots/thumbnails/IMG_4011.jpg",
}

TESTS = [
      NodeFBenchTest("hello", '{ "test": "Hello, world" }'),
    PyFBenchTest("chameleon", '{"num_of_rows": 3, "num_of_cols": 4}'),
   PyFBenchTest("float_operation", '{ "N": 300}'),
   PyFBenchTest("pyaes", '{"length_of_message": 20, "num_of_iterations": 3}'),
   PyFBenchTest("matmul", '{ "N": 300}'),
   PyFBenchTest( "json_serdes", '{{ "json_path": "{}" }}'.format( prefix_fbench('json_serdes/2.json'))),
   PyFBenchTest("video_processing", '{{ "input_path": "{}" }}'.format( prefix_fbench('dataset/video/SampleVideo_1280x720_10mb.mp4'))),
   PyFBenchTest("lr_training", '{{ "dataset_path": "{}" }}'.format( prefix_fbench('dataset/amzn_fine_food_reviews/reviews10mb.csv'))),
   PyFBenchTest("image_processing", '{{ "path": "{}" }}'.format( prefix_fbench('dataset/image/animal-dog.jpg'))),
   PyFBenchTest("linpack", '{ "N": 300}'),

   # cnn and rnn serving take too long to run
   # PyFBenchTest("rnn_serving", '{{ "language": "Scottish", "start_letters": "ABCDEFGHIJKLMNOP", "parameter_path": "{}", "model_path": "{}"}}'.format(prefix_fbench('dataset/model/rnn_params.pkl', 'dataset/model/rnn_model.pth'))),
   # PyFBenchTest("cnn_serving", '{{ "img_path": "{}", "model_path": "{}"}}'.format(prefix_fbench('dataset/image/animal-dog.jpg', 'dataset/model/rnn_model.squeezenet_weights_tf_dim_ordering_tf_kernels.h5'))),

    Test("java", "jmatmul", f"/usr/bin/java -cp {ROOT_DIR}/build/junction/samples/snapshots/java/jar/jna-5.14.0.jar:{ROOT_DIR}/build/junction/samples/snapshots/java/jar/json-simple-1.1.1.jar { ROOT_DIR}/build/junction/samples/snapshots/java/matmul/MatMul.java" + " --new_version" if NEW_VERSION else "", '{ "N": 300 }'),
]\
   + ResizerTest.template('rust', f"{ROOT_DIR}/build/junction/samples/snapshots/rust/resize-rs" + " --new-version" if NEW_VERSION else "", RESIZER_IMAGES) \
   + ResizerTest.template('java', f"/usr/bin/java -cp {ROOT_DIR}/build/junction/samples/snapshots/java/jar/jna-5.14.0.jar {ROOT_DIR}/build/junction/samples/snapshots/java/resizer/Resizer.java" + " --new_version" if NEW_VERSION else "", RESIZER_IMAGES) \
   + ResizerTest.template('go', f"{ROOT_DIR}/build/junction/samples/snapshots/go/resizer" + " --new_version" if NEW_VERSION else "", RESIZER_IMAGES)


def get_fbench_times(result_dir: str):
    if REDO_SNAPSHOT:
        for app in TESTS:
            # this should call new-version
            app.generate_images(f"{result_dir}/generate_images")

    for app in TESTS:
        second_apps = []
        for sapp in TESTS:
            if app.name == sapp.name or app.lang != sapp.lang or (
                    app.arg_name and sapp.arg_name
                    and app.arg_name == sapp.arg_name):
                continue

            second_apps.append(sapp)

        app.restore_image(f"{result_dir}/restore_images",
                          second_apps=second_apps)


def get_one_log(log_name: str):
    try:
        with open(log_name) as x:
            dat = x.read().splitlines()
    except BaseException:
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
        assert xx[
            "program"] not in progs, f"{name}: {xx['program']} already in {progs}"

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
        "cold_first_iter": d["cold"][0],
        "data_restore": d.get("data_restore"),
        "first_iter": d["warmup"][0],
        "warm_iter": d["warmup"][-1],
        "metadata_restore": d.get("metadata_restore"),
        "fs_restore": d.get("fs_restore"),
    }


def getstats(d):
    return {
        "cold_first_iter": d.get("first_iter"),
        "data_restore": d.get("data_restore"),
        # 'first_iter': d['warmup'][0],
        "warm_iter": d["times"][2],
        "metadata_restore": d.get("metadata_restore"),
        "fs_restore": d.get("fs_restore"),
    }


def get_kstats(fname: str, data, exp_n: int):
    try:
        with open(fname, "r") as f:
            for line in f.readlines():
                jx = json.loads(line)
                data[jx["key"]][expn]["jifpager_stats_ns"] = jx
    except BaseException:
        pass


def parse_fbench_times(result_dir: str):
    from pprint import pprint

    out = defaultdict(dict)

    for tag, name in RESTORE_CONFIG_SET:
        for prog, d in get_one_log(
                f"{result_dir}/restore_images_{tag}").items():
            if NEW_VERSION:
                out[prog][tag] = getstats(d)
            else:
                out[prog][tag] = getstats_old(d)
        get_kstats(f"{result_dir}/restore_images_{tag}_kstats", out, tag)

    pprint(out)
    return out


def plot_workloads(result_dir: str, data):
    workloads = list(data.keys())
    num_workloads = len(workloads)
    fig, axes = plt.subplots(num_workloads, 1, figsize=(10, 5 * num_workloads))

    if num_workloads == 1:
        axes = [axes]

    def get_colors(cat):
        return {
            "function": "tab:blue",
            "metadata": "tab:orange",
            "fs": "tab:green",
            "data": "tab:red",
            "slowdown": "tab:blue",
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
        stack1 = [(WARM_ITER, "function")]

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
            if "jifpager_stats_ns" in categories[exp]:
                jpstats = categories[exp]["jifpager_stats_ns"]
            stacks.append((
                [
                    (categories[exp]["cold_first_iter"], "function"),
                    (categories[exp]["metadata_restore"], "metadata"),
                    (categories[exp]["fs_restore"], "fs"),
                    (categories[exp]["data_restore"], "data"),
                ],
                ename,
                jpstats,
            ))

        seen = set()

        def get_lbl(label):
            if label in seen:
                return None
            seen.add(label)
            return {
                "function": "Function",
                "metadata": "Cereal restore",
                "fs": "MemFS restore",
                "data": "VMA restore",
            }.get(label, label)

        for stack, label, jpstat in stacks:
            bottom = 0
            if SUM or SLOWDOWN:
                if FUNCTION_ONLY:
                    sm = next(l[0] for l in stack if l[1] == "function")
                else:
                    sm = sum(l[0] for l in stack
                             if l[0] is not None)  # - WARM_ITER
                if SLOWDOWN:
                    sm /= WARM_ITER
                ax.bar(label, sm, color=get_colors("slowdown"))
            else:
                for val, category in stack:
                    if val is None:
                        continue
                    ax.bar(
                        label,
                        val,
                        bottom=bottom,
                        color=get_colors(category),
                        label=get_lbl(category),
                    )
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
                ha="center",
                va="center",
                color="white",
                fontsize=8,
                fontweight="bold",
            )

        ax.set_ylabel("Microseconds" if not SLOWDOWN else "Slowdown")
        # ax.set_yscale('log')
        # ax.set_ylim(1, 5e5)
        if SLOWDOWN:
            workload += f" - {WARM_ITER / 1000} ms warm iter"
        ax.set_title(workload)
        ax.legend()

    plt.tight_layout()
    plt.savefig(f'{result_dir}/graph.pdf', bbox_inches='tight')


def main():
    result_dir = f"{RESULT_DIR}/run.{datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}"
    os.system(f"mkdir -p {result_dir}")
    os.system(f"ln -sfn {result_dir} {RESULT_LINK}")
    get_fbench_times(result_dir)
    data = parse_fbench_times(result_dir)
    plot_workloads(result_dir, data)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for d in sys.argv[1:]:
            plot_workloads(d, parse_fbench_times(d))
    else:
        run_iok()
        setup_chroot()
        main()
