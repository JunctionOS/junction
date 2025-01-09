#!/usr/bin/python3

from collections import defaultdict
from datetime import datetime
from typing import List
import argparse
import atexit
import json
import matplotlib.pyplot as plt
import os
import re
import stat
import subprocess
import sys
import time
import multiprocessing
import contextlib
import psutil
import shlex
from minio import Minio

import matplotlib as mpl

mpl.use("Agg")

from termcolor import colored


def custom_excepthook(type, value, traceback):
    if type is AssertionError:
        print(colored(f'AssertionError: {value}', 'red'))
    else:
        sys.__excepthook__(type, value, traceback)


# Override the default excepthook
sys.excepthook = custom_excepthook

SCRIPT_DIR = os.path.split(os.path.realpath(__file__))[0]
ROOT_DIR = os.path.split(SCRIPT_DIR)[0]
BUILD_DIR = f"{ROOT_DIR}/build"
BIN_DIR = f"{ROOT_DIR}/bin"
INSTALL_DIR = f"{ROOT_DIR}/install"
JRUN = f"{BUILD_DIR}/junction/junction_run"
CALADAN_CONFIG = f"{BUILD_DIR}/junction/caladan_test_ts_st.config"
CALADAN_CONFIG_NOTS = f"{BUILD_DIR}/junction/caladan_test_st.config"
CALADAN_DIR = f"{ROOT_DIR}/lib/caladan"
CHROOT_DIR = f"{ROOT_DIR}/chroot"
RESULT_DIR = f"{ROOT_DIR}/results"
RESULT_LINK = f"{ROOT_DIR}/results/run.recent"
NODE_BIN = "/usr/bin/node"
NODE_PATH = f"{ROOT_DIR}/bin/node_modules"
LOADGEN_PATH = f"{CALADAN_DIR}/apps/synthetic/target/release/synthetic"

if os.path.exists(f"{INSTALL_DIR}/bin/node"):
    NODE_BIN = f"{INSTALL_DIR}/bin/node"
    NODE_PATH += f":{ROOT_DIR}/bin/node_modules_addon"

PATH_TO_FBENCH = f"{BUILD_DIR}/junction/samples/snapshots/python/function_bench/"

CONFIG = {
    'KERNEL_TRACE_RUNS': 5,
}

DROPCACHE = 1

MINIO_BUCKET = "bucket"
MINIO_DATA_PATH = "/fast/data/"
MINIO = f"{BIN_DIR}/bin/minio"
MINIO_IP = "192.168.255.255"
MINIO_MASK = "255.255.0.0"
MINIO_GATEWAY = "192.168.0.1"
MINIO_SERVER = None

parser = argparse.ArgumentParser(
    prog='jif_benchmark', description='benchmark restore times with JIFs')
parser.add_argument('--linux-baseline',
                    action=argparse.BooleanOptionalAction,
                    default=False,
                    help='run the baseline code in linux')
parser.add_argument('--use-chroot',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='use the chroot\'ed filesystem')
parser.add_argument('--elf-baseline',
                    action=argparse.BooleanOptionalAction,
                    default=False,
                    help='run an ELF baseline')
parser.add_argument('--jif-userspace-baseline',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='run a userpace restore baseline for JIF')
parser.add_argument('--kernel-exps',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='do kernel experiments')
parser.add_argument('--kernel-no-prefetch',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='do the jifpager experiment without prefetching')
parser.add_argument('--kernel-prefetch',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='do the jifpager experiment with prefetching')
parser.add_argument(
    '--kernel-prefetch-reorder',
    action=argparse.BooleanOptionalAction,
    default=True,
    help=
    'do the jipager experiment with prefetching and reordering of the intervals mentioned in the ordering segment'
)
parser.add_argument('--redo-snapshot',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='regenerate the snapshots')
parser.add_argument('--do-microbench',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='run microbenchmarks')
parser.add_argument('--do-density',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='run density experiments')
parser.add_argument('--do-sharing',
                    action=argparse.BooleanOptionalAction,
                    default=True,
                    help='run sharing experiments')
parser.add_argument('--name-filter',
                    help='regex to positively filter tests by their name')
parser.add_argument('--lang-filter',
                    help='regex to positively filter tests by their language')
parser.add_argument(
    '--arg-name-filter',
    help=
    'regex to positively filter tests by their argument name (if it exists)')
parser.add_argument(
    '-n',
    '--dry-run',
    action='store_true',
    help=
    'don\'t run the commands, but print the list of tests that would be ran and the commands that would be ran'
)
parser.add_argument(
    'dirs',
    nargs='*',
    help='instead of benchmarking, go into the dirs and plot them all')
parser.add_argument('--dropcache-sleep',
                    help='seconds to sleep after dropping caches',
                    default=10)
parser.add_argument(
    '--max-instances',
    help=
    'maximum number of concurrent instances for density/utilization experiments',
    default=0,
    type=int)
ARGS = None

RESTORE_CONFIG_SET = [
    ("linux", "Linux warm"),
    ("elf", "ELF"),
    ("itrees_jif", "JIF\nuserspace"),
    ("itrees_jif_k", "JIF\nkernel"),
    ("sa_itrees_jif_k", "JIF k\nFunction bench\npreviously run"),
    ("self_itrees_jif_k", "JIF k\nThis function\npreviously run"),
    ("plusminor_self_itrees_jif_k",
     "JIF k\nThis function\npreviously run\nplusminor"),
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

DENSITY_CONFIG_SET = {
    "no_sharing": {
        'same_image': False,
        'itrees': False,
        'prefault': False,
        'cold': True,
        'reorder': False,
        'minor': False,
    },
    "same_image": {
        'same_image': True,
        'itrees': True,
        'prefault': False,
        'cold': True,
        'reorder': False,
        'minor': False,
    },
    "sharing_libs_only": {
        'same_image': False,
        'itrees': True,
        'prefault': False,
        'cold': True,
        'reorder': False,
        'minor': False,
    },
}

# util functions


def addr_to_str(ip):
    return "{}.{}.{}.{}".format(ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff,
                                ip & 0xff)


def chroot_args():
    if not ARGS.use_chroot:
        return ""
    return f" --chroot={CHROOT_DIR} --cache_linux_fs"


def run(cmd, quiet=False):
    if not quiet:
        print(cmd)
        sys.stdout.flush()
    if not ARGS.dry_run:
        return subprocess.check_output(cmd, shell=True)


def run_quiet(cmd):
    return run(cmd, True)


class FakeProcess:
    '''fake process that has a returncode and can be waited on'''

    def __init__(self):
        self.returncode = 0

    def wait(self):
        return


def run_async(cmd):
    print(cmd)
    sys.stdout.flush()
    if ARGS.dry_run:
        return FakeProcess()
    else:
        return subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)


def kill_iok():
    run("(sudo pkill junction_run && sleep 1) || true")
    run("(sudo pkill iokerneld && sleep 1) || true")


def get_vfio_pci():
    # find first MLX Vf
    cmd = "lspci -D | grep Mellanox | grep 'Virtual' | head -n1 | awk '{print $1}'"
    pci = run_quiet(cmd).decode("utf-8").strip()
    assert pci, "couldn't find Mellanox VF to use"

    # confirm it is bound to vfio-pci
    cmd = "lspci -k -s %s | grep 'Kernel driver in use' | awk -F ': ' '{print $2}'" % pci
    driver = run_quiet(cmd).decode("utf-8").strip()
    assert driver == "vfio-pci", f"incorrect driver found: {driver}"
    return pci


def run_iok(directpath: bool = False,
            hugepages: bool = True,
            cgroup: bool = False):
    if not ARGS.dry_run and os.system("pgrep iok > /dev/null") == 0:
        return
    run(f"sudo {CALADAN_DIR}/scripts/setup_machine.sh nouintr")
    if not hugepages:
        run("echo 128 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages > /dev/null"
            )
    run("sudo rm -f /tmp/iokernel0.log")
    hugepages = "" if hugepages else "nohugepages"
    cgexec = 'cgexec -g memory:junction_iokernel' if cgroup else ''

    if directpath:
        try:
            pci = get_vfio_pci()
        except Exception:
            assert False, "Failed to find Mellanox virtual NIC (rerun setup_vfs script)"

        run(f"sudo {cgexec} {CALADAN_DIR}/iokerneld ias nobw {hugepages} vfio nicpci {pci} > /tmp/iokernel0.log 2>&1 &"
            )
    else:
        run(f"sudo {cgexec} {CALADAN_DIR}/iokerneld ias nobw {hugepages} no_hw_qdel numanode -1 -- --allow 00:00.0 --vdev=net_tap0  > /tmp/iokernel0.log 2>&1 &"
            )

    if ARGS.dry_run:
        return

    while os.system("grep -q 'running dataplan' /tmp/iokernel0.log") != 0:
        time.sleep(0.3)
        run("pgrep iokerneld > /dev/null")


@contextlib.contextmanager
def pushd(new_dir):
    prev = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(prev)


def ht_enabled():
    physical_cpus = os.popen(
        "grep 'cpu cores' /proc/cpuinfo | uniq | awk '{print $4}'").read(
        ).strip()
    logical_cpus = os.popen(
        "grep -c '^processor' /proc/cpuinfo").read().strip()

    if physical_cpus and logical_cpus:
        physical_cpus = int(physical_cpus)
        logical_cpus = int(logical_cpus)

        if logical_cpus > physical_cpus:
            return True
        else:
            return False

    return False


def build_loadgen():
    if os.path.exists(LOADGEN_PATH):
        return

    ncpu = multiprocessing.cpu_count()

    run(f"sed -i 's/-flto=auto//g' {CALADAN_DIR}/build/shared.mk")
    run(f"make -C {CALADAN_DIR} clean")
    run(f"make -C {CALADAN_DIR} -j {ncpu}")

    with pushd(f"{CALADAN_DIR}/apps/synthetic"):
        run("cargo clean")
        run("cargo b -r")

    run(r"sed -i '/^FLAGS += -march=native/a\FLAGS += -flto=auto' " +
        f"{CALADAN_DIR}/build/shared.mk")
    run(f"make -C {CALADAN_DIR} clean")
    run(f"make -C {CALADAN_DIR} -j {ncpu}")


def mem_thresh():
    return int(psutil.virtual_memory().total * 0.9)


def prefix_fbench(fname: str):
    return PATH_TO_FBENCH + fname


OBJECTS = [
    prefix_fbench('dataset/image/img3.jpeg'),
    prefix_fbench('json_serdes/1.json'),
    prefix_fbench('dataset/amzn_fine_food_reviews/dataset2.csv'),
    prefix_fbench('dataset/video/vid2.mp4'),
]


def start_minio_server():
    global MINIO_SERVER
    if MINIO_SERVER:
        return

    path = f"{CHROOT_DIR}/{MINIO_DATA_PATH}" if ARGS.use_chroot else MINIO_DATA_PATH
    _minio = run_async(f"sudo -E {MINIO} server {path} > /dev/null 2>&1")
    time.sleep(1)

    client = Minio('localhost:9000',
                   access_key='minioadmin',
                   secret_key='minioadmin',
                   secure=False)

    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)

    for obj in OBJECTS:
        client.fput_object("bucket", os.path.basename(obj), obj)

    run("sudo pkill minio")

    time.sleep(1)

    minio_cfg = "/tmp/minio.config"

    cfg = [
        f"host_addr {MINIO_IP}",
        f"host_netmask {MINIO_MASK}",
        f"host_gateway {MINIO_GATEWAY}",
        "runtime_kthreads 2",  # seems like minio does gc sometimes
        "runtime_spinning_kthreads 0",
        "runtime_guaranteed_kthreads 0",
        "runtime_priority lc",
        "runtime_quantum_us 0",
    ]

    with open(minio_cfg, "w") as f:
        f.write("\n".join(cfg))

    chroot_args = f" --chroot={CHROOT_DIR}" if ARGS.use_chroot else ""

    MINIO_SERVER = run_async(
        f"sudo -E {JRUN} {minio_cfg} {chroot_args} --env 'PATH=$PATH:/usr/bin/' -- {MINIO} server {MINIO_DATA_PATH} > /dev/null 2>&1"
    )

    atexit.register(kill_minio)

    time.sleep(1)


def kill_mem_cgroup():
    run("sudo rmdir /sys/fs/cgroup/memory/junction")
    run("sudo rmdir /sys/fs/cgroup/memory/junction_iokernel")


def kill_minio():
    run("sudo pkill junction_run || true")


def setup_mem_cgroup():
    run("sudo mkdir -p /sys/fs/cgroup/memory/junction")
    run("sudo mkdir -p /sys/fs/cgroup/memory/junction_iokernel")
    atexit.register(kill_mem_cgroup)
    run(f"echo {mem_thresh()}| sudo tee /sys/fs/cgroup/memory/junction/memory.limit_in_bytes"
        )


def kill_chroot():
    run(f"{ROOT_DIR}/scripts/chroot_mount.sh -u || true")
    if jifpager_installed():
        run(f"sudo rm -f {CHROOT_DIR}/dev/jif_pager")


def setup_chroot():
    if not ARGS.use_chroot:
        return
    run(f"sudo mkdir -p {CHROOT_DIR}/{BIN_DIR} {CHROOT_DIR}/{BUILD_DIR} {CHROOT_DIR}/{INSTALL_DIR}"
        )

    # clean old mounts
    kill_chroot()
    run(f"{ROOT_DIR}/scripts/chroot_mount.sh")

    if jifpager_installed():
        st = os.stat("/dev/jif_pager")
        major = os.major(st.st_rdev)
        minor = os.minor(st.st_rdev)

        run(f"sudo mknod -m 666 {CHROOT_DIR}/dev/jif_pager c {major} {minor} || true"
            )

    atexit.register(kill_chroot)


def jifpager_installed():
    try:
        return ARGS.kernel_exps and stat.S_ISCHR(
            os.stat("/dev/jif_pager").st_mode)
    except BaseException:
        return False


def set_trace(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/trace")


def set_wait_for_pages(val):
    run(f"echo {val} | sudo tee /sys/kernel/jif_pager/wait_for_pages")


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
    if ARGS.dry_run:
        return

    for i in range(DROPCACHE):
        if i > 0:
            time.sleep(int(ARGS.dropcache_sleep))
        run("echo 3 | sudo tee /proc/sys/vm/drop_caches")


# Test definitions


class Test:

    @classmethod
    def template(cls,
                 lang: str,
                 name: str,
                 cmd: str,
                 arg_map,
                 new_version_fn=lambda x: x,
                 s3=False,
                 do_second_apps=True):
        """
        punch out a template of tests, where the arg_map is a map from arg_name -> arg
        return a list of Tests
        """
        return [
            cls(lang, name, cmd, args, arg_name, new_version_fn)
            for arg_name, args in arg_map.items()
        ]

    def __init__(self,
                 lang: str,
                 name: str,
                 cmd: str,
                 args: str,
                 arg_name: str = "",
                 env: str = "",
                 new_version_fn=lambda x: x,
                 s3=False,
                 do_second_apps=True):
        self.lang = lang
        self.name = name
        self.raw_cmd = cmd
        self.cmd = new_version_fn(cmd)
        self.args = args
        self.stop_count = 2 if lang == 'java' else 1
        self.arg_name = arg_name
        self.env = env
        self.s3 = s3
        self.do_second_apps = do_second_apps

    def id(self):
        if self.arg_name:
            return f"{self.lang}_{self.name}_{self.arg_name}"
        else:
            return f"{self.lang}_{self.name}"

    def __repr__(self):
        return f"{self.name}: lang={self.lang}, id={self.id()}" + (
            f" arg_name={self.arg_name}" if self.arg_name else "")

    def baseline(self, result_dir: str):
        run(f"DONTSTOP=1 {self.raw_cmd} >> {result_dir}/restore_images_linux 2>&1"
            )

    def _env(self):
        return f"-E {self.env}" if self.env else ""

    def snapshot_prefix(self, with_chroot=False):
        func_id = self.id()

        if with_chroot and ARGS.use_chroot:
            return f"{CHROOT_DIR}/tmp/{func_id}"

        return f"/tmp/{func_id}"

    def jrun(self,
             jargs,
             cmd,
             log,
             ip_alloc=None,
             quiet=False,
             idx=0,
             bg=False):
        if ip_alloc is None:
            ip_alloc = IPAllocator()

        client = None

        server_ip = ip_alloc.next()
        client_ip = ip_alloc.next()

        server_cfg = f"/tmp/server{idx}.config"
        client_cfg = f"/tmp/client{idx+1}.config"

        procs = []

        if hasattr(self, 'run_client'):
            gen_lc_config(client_cfg, client_ip, ip_alloc.get_netmask(),
                          ip_alloc.get_base())
            client = self.run_client(client_cfg, client_ip, server_ip,
                                     f"{log}_client")
            if bg:
                procs.append(client)

        gen_lc_config(server_cfg, server_ip, ip_alloc.get_netmask(),
                      ip_alloc.get_base())

        if bg:
            server = run_async(
                f"sudo -E {JRUN} {server_cfg} {jargs} -- {cmd} >> {log} 2>&1")
            procs.append(server)
        else:
            run(f"sudo -E {JRUN} {server_cfg} {jargs} -- {cmd} >> {log} 2>&1")

        if client and not bg:
            client.wait()

        return procs

    def snapshot_elf(self, output_log: str):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()} {self._env()}"
        prefix = self.snapshot_prefix()

        self.jrun(
            f"{junction_args} {chroot_args()} --snapshot-prefix {prefix}",
            self.cmd, f"{output_log}_snap_elf")

    def snapshot_jif(self, output_log: str):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()} {self._env()}"
        prefix = self.snapshot_prefix()

        self.jrun(
            f"{junction_args} {chroot_args()} --jif --madv_remap --snapshot-prefix {prefix}",
            self.cmd, f"{output_log}_snap_jif")

    def process_itree(self, output_log: str):
        prefix = self.snapshot_prefix(with_chroot=True)
        chroot_dir = CHROOT_DIR if ARGS.use_chroot else ''

        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}.jif {prefix}_itrees.jif build-itrees {chroot_dir} >> {output_log}_build_itree 2>&1"
            )

    def process_fault_order(self, output_log: str, itrees: bool = True):
        '''add ordering to the jif'''

        itrees = "_itrees" if itrees else ""
        prefix = self.snapshot_prefix(with_chroot=True)

        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}{itrees}.jif {prefix}{itrees}_ord_reorder.jif add-ord --setup-prefetch {prefix}.ord >> {output_log}_add_ord_reord 2>&1"
            )
        run(f"stdbuf -e0 -i0 -o0 {BUILD_DIR}/jiftool {prefix}{itrees}.jif {prefix}{itrees}_ord.jif add-ord {prefix}.ord >> {output_log}_add_ord 2>&1 "
            )

    def restore_elf(self, output_log: str, cold: bool = True):
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}"
        prefix = self.snapshot_prefix()

        if cold:
            dropcache()

        self.jrun(f"-r {junction_args} {chroot_args()}",
                  f"{prefix}.metadata {prefix}.elf", f"{output_log}_elf")

    def userspace_restore_jif(self,
                              output_log: str,
                              trace: bool = False,
                              itrees: bool = False,
                              reorder: bool = False,
                              cold: bool = True):

        def construct_jif_fname(self, itrees: bool, reorder: bool) -> str:
            fname = self.snapshot_prefix()
            if itrees:
                fname += '_itrees'
            if reorder:
                fname += '_ord_reorder'
            fname += '.jif'
            return fname

        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}"
        prefix = self.snapshot_prefix()
        mem_flags = f"--stackswitch --mem-trace --mem-trace-out {prefix}.ord" if trace else ""

        jif_fname = construct_jif_fname(self, itrees, reorder)

        if cold:
            dropcache()

        self.jrun(f"{junction_args} {mem_flags} {chroot_args()} --jif -r",
                  f"{prefix}.jm {jif_fname}", f"{output_log}_jif")

    def jifpager_restore_jif(self,
                             output_log: str,
                             prefault: bool = False,
                             cold: bool = False,
                             minor: bool = False,
                             fault_around: bool = True,
                             measure_latency: bool = False,
                             wait_for_pages: bool = False,
                             reorder: bool = True,
                             trace: bool = False,
                             second_apps=[]):
        set_fault_around(1 if fault_around else 0)
        set_prefault(1 if prefault else 0)
        set_prefault_minor(1 if minor else 0)
        set_measure_latency(1 if measure_latency else 0)
        set_wait_for_pages(1 if wait_for_pages else 0)
        set_trace(1 if trace else 0)
        jifpager_reset()

        if cold:
            dropcache()

        suffix = "_reorder" if reorder else ""

        procs = []

        ip_alloc = IPAllocator()

        for app in second_apps:
            if app.s3:
                start_minio_server()
                break

        n = 0
        for idx, sapp in enumerate(second_apps):
            junction_args = f"--function_arg '{sapp.args}' --function_name {sapp.id()}"
            prefix = sapp.snapshot_prefix()

            p = self.jrun(f"{chroot_args()} {junction_args} --jif -rk",
                          f"{prefix}.jm {prefix}_itrees_ord{suffix}.jif",
                          f"{output_log}_itrees_jif_k_second_app_{sapp.id()}",
                          idx=n,
                          bg=True,
                          ip_alloc=ip_alloc)

            n += len(p)

            for proc in p:
                procs.append(proc)

        for proc, app in zip(procs, second_apps):
            proc.wait()
            assert proc.returncode == 0, f"failed to run function: {app.id()}"

        jifpager_reset()
        junction_args = f"--function_arg '{self.args}' --function_name {self.id()}"
        prefix = self.snapshot_prefix()

        self.jrun(f"{chroot_args()} {junction_args} --jif -rk",
                  f"{prefix}.jm {prefix}_itrees_ord{suffix}.jif",
                  f"{output_log}_itrees_jif_k",
                  idx=n,
                  ip_alloc=ip_alloc)

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

        stats["wait_for_pages"] = wait_for_pages
        stats["prefault"] = prefault
        stats["cold"] = cold
        stats['key'] = self.id()
        with open(f"{output_log}_itrees_jif_k_kstats", "a") as f:
            f.write(json.dumps(stats))
            f.write('\n')

    def do_kernel_trace(self, output_log: str):
        path = self.snapshot_prefix(with_chroot=True)
        for i in range(CONFIG['KERNEL_TRACE_RUNS']):
            time.sleep(1)
            self.jifpager_restore_jif(f"{output_log}_build_ord",
                                      cold=False,
                                      prefault=True,
                                      minor=i % 2 == 0,
                                      fault_around=False,
                                      trace=True)
            run(f"sudo rm -f /tmp/ord")
            run(f"sudo cat /sys/kernel/debug/mem_trace {path}.ord > /tmp/ord")
            run(f"sort -n /tmp/ord | sudo tee {path}.ord > /dev/null")
            self.process_fault_order(output_log)

    def generate_images(self, output_log: str):
        if hasattr(self, 'run_client'):
            kill_iok()
            run_iok(hugepages=True, directpath=True)

        if self.s3:
            start_minio_server()

        if ARGS.elf_baseline:
            self.snapshot_elf(output_log)

        self.snapshot_jif(output_log)
        self.process_itree(output_log)

        # generate ord
        self.userspace_restore_jif(f"{output_log}_build_ord", trace=True)
        self.process_fault_order(output_log)

        # re-generate ord with kernel tracer to catch more faults
        if jifpager_installed():
            self.do_kernel_trace(output_log)

        # add ordering to non-itree JIFs for dedup experiments
        self.process_fault_order(output_log, itrees=False)

    def restore_image(self, output_log: str, second_apps=[]):
        if hasattr(self, 'run_client'):
            kill_iok()
            run_iok(hugepages=True, directpath=True)

        if self.s3:
            start_minio_server()

        if ARGS.elf_baseline:
            self.restore_elf(output_log)

        if ARGS.jif_userspace_baseline:
            self.userspace_restore_jif(output_log, itrees=True)

        # use the reorder file with userspace restore (increases VMA setup
        # costs)
        if False:
            self.userspace_restore_jif(f"{output_log}_reorder",
                                       reorder=True,
                                       itrees=True)

        if jifpager_installed():
            if ARGS.kernel_no_prefetch:
                # Kernel module restore (no prefetching)
                self.jifpager_restore_jif(output_log,
                                          prefault=False,
                                          cold=True,
                                          reorder=True)

            if ARGS.kernel_prefetch:
                # Prefault pages
                self.jifpager_restore_jif(f"{output_log}_prefault",
                                          prefault=True,
                                          cold=True,
                                          reorder=False)
                # self.jifpager_restore_jif(f"{output_log}_prefault_minor,
                # minor=True, prefault=True, cold=True, reorder=False)

            if ARGS.kernel_prefetch_reorder:
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
                for tag, function in [("simple", "float_operation"),
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

            if second_apps and self.do_second_apps:
                self.jifpager_restore_jif(f"{output_log}_sa",
                                          minor=False,
                                          prefault=False,
                                          cold=True,
                                          reorder=False,
                                          second_apps=second_apps)

            # self.jifpager_restore_jif(output_log, minor=False, prefault=False, cold=True, reorder=True, second_apps=second_apps)
            # self.jifpager_restore_jif(f"{output_log}_self", minor=False, prefault=False, cold=True, reorder=False, second_apps=second_apps)

            if self.do_second_apps:
                self.jifpager_restore_jif(f"{output_log}_self",
                                          minor=False,
                                          prefault=False,
                                          cold=True,
                                          reorder=True,
                                          second_apps=[self])
                self.jifpager_restore_jif(f"{output_log}_plusminor_self",
                                          minor=True,
                                          prefault=False,
                                          cold=True,
                                          reorder=True,
                                          second_apps=[self])


class PyFBenchTest(Test):

    def __init__(self,
                 display_name: str,
                 s3=False,
                 do_second_apps=True,
                 fname=None,
                 **args):

        def new_version_fn(cmd):
            return cmd.replace('run.py', 'new_runner.py')

        if fname is None:
            fname = display_name

        super().__init__(
            'python',
            name,
            f"{ROOT_DIR}/bin/venv/bin/python3 -u  {BUILD_DIR}/junction/samples/snapshots/python/function_bench/run.py {fname}",
            json.dumps(args),
            "",
            new_version_fn=new_version_fn,
            s3=s3,
            do_second_apps=do_second_apps)


class NodeFBenchTest(Test):

    def __init__(self, name: str, s3=False, do_second_apps=True, **args):
        super().__init__(
            'node',
            name,
            f"{NODE_BIN} --expose-gc {BUILD_DIR}/junction/samples/snapshots/node/function_bench/run.js {name}",
            json.dumps(args),
            env=f"NODE_PATH={NODE_PATH}",
            s3=s3,
            do_second_apps=do_second_apps)


class PyGRPCFBenchTest(Test):

    def __init__(self, name: str, s3=False, **args):
        self.client = f"{ROOT_DIR}/bin/venv/bin/python3 {BUILD_DIR}/junction/samples/snapshots/python/function_bench/client.py"
        super().__init__(
            'pygrpc',
            name,
            f"{ROOT_DIR}/bin/venv/bin/python3 -u {BUILD_DIR}/junction/samples/snapshots/python/function_bench/server.py {name}",
            json.dumps(args),
            "",
            s3=s3,
            do_second_apps=False)

    def run_client(self, client_cfg, client_ip, server_ip, log):
        client = run_async(
            f"sudo -E {JRUN} {client_cfg} {chroot_args()} -- {self.client} {addr_to_str(server_ip)} > {log} 2>&1"
        )
        time.sleep(1)
        return client


class ResizerTest(Test):

    @classmethod
    def template(cls, lang: str, cmd: str, arg_map, new_version_fn):
        """
        punch out a template of tests, where the arg_map is a map from arg_name -> arg
        return a list of Tests
        """
        return [
            cls(lang, cmd, args, arg_name, new_version_fn)
            for arg_name, args in arg_map.items()
        ]

    def __init__(self, lang: str, cmd: str, args: str, arg_name: str,
                 new_version_fn):
        super().__init__(lang,
                         'resizer',
                         cmd,
                         args,
                         arg_name,
                         new_version_fn=new_version_fn)


RESIZER_IMAGES = {
    "large": f"{BUILD_DIR}/junction/samples/snapshots/images/IMG_4011.jpg",
    "tiny": f"{BUILD_DIR}/junction/samples/snapshots/thumbnails/IMG_4011.jpg",
}

TESTS = [
   NodeFBenchTest("hello", test="Hello, world"),
   NodeFBenchTest("float_operation", N=300),
   NodeFBenchTest("image_processing", path=prefix_fbench('dataset/image/animal-dog.jpg')),
   NodeFBenchTest("json_serdes", json_path=prefix_fbench('json_serdes/2.json')),
   PyFBenchTest("chameleon", num_of_rows=10, num_of_cols=15),


   PyFBenchTest("float_operation", N=300),
   PyFBenchTest("pyaes", length_of_message=100, num_of_iterations=1), # reap does one iteration
   PyFBenchTest("matmul", N=300),
   PyFBenchTest( "json_serdes", json_path=prefix_fbench('json_serdes/2.json')),
   PyFBenchTest("lr_training", dataset_path=prefix_fbench('dataset/amzn_fine_food_reviews/reviews10mb.csv')),
   PyFBenchTest("image_processing",path=prefix_fbench('dataset/image/animal-dog.jpg')),
   PyFBenchTest("linpack", N=300),
   PyFBenchTest("helloworld", message="Hello, world!"),
   PyFBenchTest("json_serdes_s3", s3=True, json_file='1.json', minio_addr=f'{MINIO_IP}:9000'),
   PyFBenchTest("image_rotate_s3", s3=True, image='img3.jpeg',  minio_addr=f'{MINIO_IP}:9000'),
   PyFBenchTest("lr_training_s3", s3=True, data='dataset2.csv', minio_addr=f'{MINIO_IP}:9000'),
   PyFBenchTest("video_processing_s3", s3=True, vid='vid2.mp4', minio_addr=f'{MINIO_IP}:9000'),

   PyGRPCFBenchTest("helloworld", message="Hello, world!"),
   PyGRPCFBenchTest("chameleon", num_of_rows=10, num_of_cols=15),
   PyGRPCFBenchTest("pyaes", length_of_message=100, num_of_iterations=3),
   # cnn and rnn serving take too long to run
   # PyFBenchTest("rnn_serving", '{{ "language": "Scottish", "start_letters": "ABCDEFGHIJKLMNOP", "parameter_path": "{}", "model_path": "{}"}}'.format(prefix_fbench('dataset/model/rnn_params.pkl', 'dataset/model/rnn_model.pth'))),
   # PyFBenchTest("cnn_serving", '{{ "img_path": "{}", "model_path": "{}"}}'.format(prefix_fbench('dataset/image/animal-dog.jpg', 'dataset/model/rnn_model.squeezenet_weights_tf_dim_ordering_tf_kernels.h5'))),
   # PyFBenchTest("video_processing", input_path=prefix_fbench('dataset/video/SampleVideo_1280x720_10mb.mp4')),

   Test("java", "matmul", f"/usr/bin/java -cp {BUILD_DIR}/junction/samples/snapshots/java/jar/jna-5.14.0.jar:{BUILD_DIR}/junction/samples/snapshots/java/jar/json-simple-1.1.1.jar {BUILD_DIR}/junction/samples/snapshots/java/matmul/MatMul.java", '{ "N": 300 }', new_version_fn=lambda x: x + " --new_version"),
]\
        + ResizerTest.template('rust', f"{BUILD_DIR}/junction/samples/snapshots/rust/resize-rs", RESIZER_IMAGES, new_version_fn=lambda x: x + " --new-version") \
        + ResizerTest.template('java', f"/usr/bin/java -cp {BUILD_DIR}/junction/samples/snapshots/java/jar/jna-5.14.0.jar {BUILD_DIR}/junction/samples/snapshots/java/resizer/Resizer.java", RESIZER_IMAGES, new_version_fn = lambda x: x + " --new_version") \
        + ResizerTest.template('go', f"{BUILD_DIR}/junction/samples/snapshots/go/resizer", RESIZER_IMAGES, new_version_fn=lambda x: x + " --new_version")

"""
for iters in [1, 100, 500]:
    for pages in [1, 100, 1000, 10000, 100000, 1000000]:
        TESTS.append(
            PyFBenchTest(f"synthetic{pages}_{iters}",
                         fname="synthetic",
                         num_pages=pages,
                         ops_per_page=iters))
"""

def run_microbenchmark(result_dir: str, tests):
    for app in tests:
        second_apps = []
        for sapp in tests:
            if app.name == sapp.name or app.lang != sapp.lang or (
                    app.arg_name and sapp.arg_name
                    and app.arg_name == sapp.arg_name):
                continue

            second_apps.append(sapp)

        app.restore_image(f"{result_dir}/restore_images",
                          second_apps=second_apps)


def get_img_suffix(cfg):
    itrees = cfg['itrees']
    prefault = cfg['prefault']
    reorder = cfg['reorder']

    suffix = "_itrees" if itrees else ""
    suffix = f"{suffix}_ord" if prefault else suffix
    suffix = f"{suffix}_reorder" if reorder else suffix
    return suffix


# It's hard to use proc.kill() to terminate a process, so this function
# recursively scans the process tree and terminates every node directly.
def kill_pid_and_kids(pid, force_kill=False):
    try:
        kids = subprocess.check_output(
            shlex.split(f"ps -o pid --ppid {pid} --noheaders")).splitlines()
    except Exception:
        kids = []
    for i in kids:
        kill_pid_and_kids(int(i.strip()))
    sig = "SIGKILL" if force_kill else "SIGINT"
    run_quiet(f"sudo kill -{sig} {pid} 2> /dev/null || true")


class RunningProc:

    def __init__(self, proc, app, output_file, ip):
        self.proc = proc
        self.app = app
        self.output_file = output_file
        self.ip = ip

    def get_output_file(self):
        return self.output_file

    def wait(self):
        self.proc.wait()
        assert self.proc.returncode == 0, f"failed to run, log = {self.output_file}"

    def check_alive(self):
        return self.proc.poll() is None

    def assert_alive(self):
        assert self.check_alive(), f"proc is dead, log = {self.output_file}"

    def get_ip(self):
        return self.ip

    def get_app(self):
        return self.app

    def kill(self):
        kill_pid_and_kids(self.proc.pid, False)
        kill_pid_and_kids(self.proc.pid, True)


def setup_async_images(apps, copies_per_app: int, cfg):
    if cfg['same_image']:
        return
    suffix = get_img_suffix(cfg)
    path = CHROOT_DIR if ARGS.use_chroot else ""

    for app in apps:
        img = f"{app.snapshot_prefix()}{suffix}"
        run(f"parallel cp {path}{img}.jif {path}{img}{{}}.jif ::: " +
            " ".join(str(i) for i in range(copies_per_app)))


def rm_async_images(apps, copies_per_app, cfg):
    if cfg['same_image']:
        return
    suffix = get_img_suffix(cfg)
    path = CHROOT_DIR if ARGS.use_chroot else ""

    for app in apps:
        img = f"{app.snapshot_prefix()}{suffix}"
        for i in range(copies_per_app):
            os.unlink(f"{path}{img}{i}.jif")


def clear_mem_cgroup(name):
    file = f"/sys/fs/cgroup/memory/{name}/memory.max_usage_in_bytes"
    run(f"echo 0 | sudo tee {file} > /dev/null")


def get_mem_cgroup(name):
    file = f"/sys/fs/cgroup/memory/{name}/memory.max_usage_in_bytes"
    with open(file, "r") as f:
        return int(int(f.readlines()[0]))


def clear_cgroup():
    clear_mem_cgroup("junction")
    clear_mem_cgroup("junction_iokernel")


def get_and_reset_memusage():
    usage = get_mem_cgroup("junction") + get_mem_cgroup("junction_iokernel")
    clear_mem_cgroup("junction")
    clear_mem_cgroup("junction_iokernel")
    return usage


def gen_be_config(file, ip, mask, gw, be_kthreads=2):
    cfg = [
        f"host_addr {addr_to_str(ip)}",
        f"host_netmask {addr_to_str(mask)}",
        f"host_gateway {addr_to_str(gw)}",
        f"runtime_kthreads {be_kthreads}",
        "runtime_spinning_kthreads 0",
        "runtime_guaranteed_kthreads 0",
        "runtime_priority be",
        "runtime_quantum_us 2000",
        "enable_transparent_hugepages 1",
    ]
    with open(file, "w") as f:
        f.write("\n".join(cfg))


def gen_lc_config(file, ip, mask, gw):
    lc_kthreads = 1
    cfg = [
        f"host_addr {addr_to_str(ip)}",
        f"host_netmask {addr_to_str(mask)}",
        f"host_gateway {addr_to_str(gw)}",
        f"runtime_kthreads {lc_kthreads}",
        "runtime_spinning_kthreads 0",
        "runtime_guaranteed_kthreads 0",
        "runtime_priority lc",
        "runtime_quantum_us 0",
    ]
    os.system(f"sudo rm -f {file}")
    with open(file, "w") as f:
        f.write("\n".join(cfg))


class IPAllocator:

    def __init__(self):
        self.base = 3232266241  # (192 << 24) + (168 << 16) + (120 << 8) + 1
        self.netmask = 0xffff0000  # 255.255.0.0
        self.assigned = 1  # reserve one for gateway
        pass

    def get_base(self):
        return self.base

    def get_netmask(self):
        return self.netmask

    def next(self):
        nxt = self.base + self.assigned
        self.assigned += 1
        # check for overflow out of our subnet mask
        assert (nxt & ~self.netmask) > (
            self.base & ~self.netmask), f"{addr_to_str(nxt)} overflows"
        return nxt


def restore_images_async(output_prefix: str,
                         apps,
                         cfg,
                         ip_alloc: IPAllocator,
                         copies_per_app: int = 1,
                         cgroup: bool = True,
                         wait_for_apps: bool = False):
    cold = cfg['cold']
    minor = cfg['minor']
    _reorder = cfg['reorder']
    prefault = cfg['prefault']
    _itrees = cfg['itrees']
    same_image = cfg['same_image']

    set_fault_around(1)
    set_prefault(1 if prefault else 0)
    set_prefault_minor(1 if minor else 0)
    set_measure_latency(0)
    set_wait_for_pages(1)
    set_trace(0)

    _path = CHROOT_DIR if ARGS.use_chroot else ""

    jifpager_reset()

    if cold:
        dropcache()

    # reset mem usage
    if cgroup:
        clear_cgroup()

    procs = []
    for app in apps:
        for i in range(copies_per_app):
            prefix = app.snapshot_prefix()
            img = f"{prefix}{get_img_suffix(cfg)}{i if not same_image else ''}"
            junction_args = f" --function_name {app.id()} --function_arg '{app.args}' --keep_alive"
            caladan_config = f"/tmp/{app.id()}_{i}.config"
            ip = ip_alloc.next()
            gen_be_config(caladan_config, ip, ip_alloc.get_netmask(),
                          ip_alloc.get_base(), 1 if "node" in app.id() else 2)
            output = f"{output_prefix}_{app.id()}_{i}"

            predash_args = " --jif -r"
            postdash_args = f"{prefix}.jm {img}.jif"

            if False:
                predash_args = f"{app._env()} --jif --snapshot-prefix {prefix}"
                postdash_args = app.cmd

            proc = run_async(
                f"sudo -E {'cgexec -g memory:junction' if cgroup else ''} {JRUN} {caladan_config} {chroot_args()} {junction_args} {predash_args} -- {postdash_args}  >> {output} 2>&1"
            )
            procs.append(RunningProc(proc, app, output, ip))

    if not wait_for_apps:
        return procs

    # Wait for each app to print a line with DATA, happens after the first
    # function execution.
    print("Waiting for apps to initialize")
    for p in procs:
        while os.system(f"grep -q DATA {p.get_output_file()}") != 0:
            time.sleep(0.1)
            p.assert_alive()
        p.assert_alive()
    print("Apps initialized")
    return procs


def run_density(result_dir: str, tests, count=10, step=1):
    setup_mem_cgroup()

    # log apps to regenerate figs
    with open(f"{result_dir}/apps", "a") as f:
        for app in tests:
            f.write(f"{app.id()}\n")

    with open(f"{result_dir}/params", "a") as f:
        f.write(f"{count}, {step}")

    for name, cfg in DENSITY_CONFIG_SET:
        setup_async_images(tests, count, cfg)
        for i in range(step, count + 1, step):
            output_log = f"{result_dir}/density_{name}_{count}"
            restore_images_async(output_log,
                                 name,
                                 tests,
                                 cfg,
                                 count=i,
                                 cgroup=True)

        rm_async_images(tests, count, cfg)


def start_vmstat(prefix):
    cmd = f"taskset -c 0 /bin/bash -c 'while ps -p {os.getpid()} > /dev/null; do vmstat -s; cat /proc/meminfo; sleep 1; done | ts %s > {prefix}_vmstat'"
    return run_async(cmd)


def run_loadgen_async(output_prefix: str,
                      running_procs: List[RunningProc],
                      ip_alloc: IPAllocator,
                      runtime: int = None):
    loadgen_kthreads = 4
    depth = 5
    runtime = runtime or 10

    assert loadgen_kthreads % 2 == 0, "with HT enabled need even #"

    by_app = defaultdict(list)
    app_args = {}

    for proc in running_procs:
        by_app[proc.app.id()].append(proc)
        if proc.app.id() not in app_args:
            app_args[proc.app.id()] = proc.app.args
        assert app_args[proc.app.id(
        )] == proc.app.args, "assuming app ip match means arguments match"

    base_loadgen_ip = None
    procs = []

    for index, app_id in enumerate(by_app.keys()):
        cfg = []
        ip = ip_alloc.next()
        if index == 0:
            base_loadgen_ip = ip
        cfg = [
            f"host_addr {addr_to_str(ip)}",
            f"host_netmask {addr_to_str(ip_alloc.get_netmask())}",
            f"host_gateway {addr_to_str(ip_alloc.get_base())}",
            f"runtime_kthreads {loadgen_kthreads}",
            f"runtime_guaranteed_kthreads {loadgen_kthreads}",
            "runtime_priority lc",
            "runtime_quantum_us 0",
            "enable_transparent_hugepages 1",
        ]

        lgpath = f"/tmp/loadgen_{app_id}.config"
        with open(lgpath, "w") as f:
            f.write("\n".join(cfg))

        ips = [addr_to_str(proc.ip) for proc in by_app[app_id]]
        addrs = " ".join(f"{ip}:43" for ip in ips)
        output = f"{output_prefix}_loadgen_{app_id}_out"
        if len(by_app) == 1:
            bflags = ""
        elif index == 0:
            bflags = f"--leader --barrier-peers {len(by_app)}"
        else:
            bflags = f" --leader-ip={addr_to_str(base_loadgen_ip)} "
        proc = run_async(
            f"sudo -E {LOADGEN_PATH} {addrs} --closed_bench --config {lgpath} {bflags} --runtime {runtime} --mode runtime-client --transport tcp --protocol serverless --threads 1 --depth {depth} --function_args='{app_args[app_id]}' >> {output} 2>&1"
        )
        procs.append(RunningProc(proc, None, output, ip))
    return procs


def clean_running():
    os.system("sudo pkill junc")
    kill_iok()


def run_cfg(output_log,
            tests,
            cfg,
            copies_per_app,
            runtime=None,
            nosetup=False):
    if not nosetup:
        setup_async_images(tests, copies_per_app, cfg)

    if cfg.get("cold", True):
        dropcache()

    kill_iok()
    run_iok(hugepages=False, directpath=True, cgroup=True)

    mem_recorder = start_vmstat(output_log)

    ip_alloc = IPAllocator()
    app_procs = restore_images_async(output_log,
                                     tests,
                                     cfg,
                                     ip_alloc,
                                     copies_per_app=copies_per_app,
                                     cgroup=True,
                                     wait_for_apps=True)

    lg_procs = run_loadgen_async(output_log,
                                 app_procs,
                                 ip_alloc,
                                 runtime=runtime)

    print("Waiting for loadgen(s) to terminate")
    for loadgen_proc in lg_procs:
        loadgen_proc.wait()

    kill_pid_and_kids(mem_recorder.pid)
    kill_pid_and_kids(mem_recorder.pid, True)
    mem_recorder.wait()

    print("Cleaning up procs")
    for a in app_procs:
        a.assert_alive()
    os.system("sudo pkill junc")
    kill_iok()

    # Wait for all shared memory to be released
    print("Waiting for shmem cleanup...")
    while os.system("ipcs -u | grep -q 'segments allocated 0'") != 0:
        time.sleep(0.1)
    print("Clean up done")

    if not nosetup:
        rm_async_images(tests, copies_per_app, cfg)


def run_sharing(result_dir: str, tests, count):

    atexit.register(lambda: os.system("sudo pkill junc"))

    # apps for regenerating results
    with open(f"{result_dir}/apps", "a") as f:
        for app in tests:
            f.write(f"{app.id()}\n")

    # test names for regenerating results
    with open(f"{result_dir}/experiments", "a") as f:
        for name, _ in DENSITY_CONFIG_SET:
            f.write(f"{name}\n")

    setup_mem_cgroup()

    if ARGS.max_instances == 0:
        name, cfg = (("no_sharing"), {
            'same_image': False,
            'itrees': False,
            'prefault': False,
            'cold': True,
            'reorder': False,
            'minor': False,
        })

        # See what memory usage is like with 25 copies per app
        copies_per_app = 10
        output_log = f"{result_dir}/sharing1_{name}_{copies_per_app}"
        run_cfg(output_log, tests, cfg, copies_per_app)

        # set 90% of currently free memory as the memory threshold
        mem_thresh = psutil.virtual_memory().free * 0.9
        max_mem_usage = get_and_reset_memusage()

        count = int(10 * (mem_thresh / max_mem_usage))
    else:
        count = ARGS.max_instances

    # instance count for regenerating results
    with open(f"{result_dir}/sharing_params", "a") as f:
        f.write(f"{count}\n")

    # run baseline, each app alone at max cores with full sharing
    name, cfg = (("same_image"), {
        'same_image': True,
        'itrees': True,
        'prefault': True,
        'cold': True,
        'reorder': True,
        'minor': True,
    })
    for app in tests:
        output_log = f"{result_dir}/sharing2_{count}"
        run_cfg(output_log, [app], cfg, multiprocessing.cpu_count())

    clear_cgroup()

    # run experiment
    mem_usage = dict()
    for name, cfg in DENSITY_CONFIG_SET:
        output_log = f"{result_dir}/sharing3_{name}_{count}"
        run_cfg(output_log, tests, cfg, count)
        mem_usage[name] = get_and_reset_memusage()

    with open(f'{result_dir}/mem_usage', 'w') as f:
        json.dump(mem_usage, f)


def parse_sharing_logs(result_dir):
    with open(f"{result_dir}/apps", "r") as f:
        apps = [app.split('\n')[0] for app in f.readlines()]

    with open(f"{result_dir}/experiments", "r") as f:
        exps = [exp.split('\n')[0] for exp in f.readlines()]

    with open(f"{result_dir}/sharing_params", "r") as f:
        count = int(f.readline())

    def getrps(filename):
        with open(f"{result_dir}/{filename}", "r") as f:
            lines = f.readlines()
        for line in lines:
            if not line.startswith("RPS: "):
                continue
            return int(line.split()[1])
        assert False, f"{filename} has no RPS."

    baseline = defaultdict(dict)
    results = defaultdict(dict)
    for app in apps:
        baseln = f"sharing2_{count}_loadgen_{app}_out"
        baseline[app][app] = getrps(baseln)

        for exp in exps:
            fn = f"sharing3_{exp}_{count}_loadgen_{app}_out"
            results[exp][app] = getrps(fn)

    baseline_slowdowns = dict()
    sharing_slowdowns = dict()
    for name in exps:
        b_slowdown = 0
        s_slowdown = 0
        for app in apps:
            b_slowdown += results[name][app] / baseline[app][app]
            if name != 'itrees_':
                s_slowdown += results[name][app] / results['same_image'][app]

        baseline_slowdowns[name] = b_slowdown

        if name != 'same_image':
            sharing_slowdowns[name] = s_slowdown / len(apps)

    f = open(f'{result_dir}/mem_usage')
    mem = json.load(f)

    print(f'Sharing results for {count * len(apps)} instances running {apps}')
    print('Slowdowns:')
    for k in baseline_slowdowns.keys():
        print(
            f"    {k}: {baseline_slowdowns[k] * 100.0:.2f}% of baseline throughput"
        )

    # print('')
    # print('Slowdowns compared to n instances sharing the same image')
    # for k in sharing_slowdowns.keys():
    #     print(f"{k}: {sharing_slowdowns[k]}")

    baseline_mem = mem['same_image']
    print('Memory usage')

    for k in mem.keys():
        if k == 'same_image':
            continue
        pct_increase = (mem[k] - baseline_mem) / baseline_mem * 100.0

        print(f"    {k}: {pct_increase:.2f}% over baseline")


def get_one_log(log_name: str):
    try:
        with open(log_name) as x:
            dat = x.read().splitlines()
    except BaseException:
        return {}

    progs = {}
    prev_restore = None
    for line in dat:
        if "DATA  " not in line:
            if "restore time" in line:
                prev_restore = line
            continue
        lx = line.split("DATA  ")[-1].strip()
        xx = json.loads(lx)
        assert xx[
            "program"] not in progs, f"{xx['program']} already in {progs}"

        if prev_restore:
            line = prev_restore.split("restore time")[1].split()
            xx["metadata_restore"] = int(line[2])
            xx["data_restore"] = int(line[4])
            xx["fs_restore"] = int(line[6])
            prev_restore = None

        progs[xx["program"]] = xx

    return progs


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
                data[jx["key"]][exp_n]["jifpager_stats_ns"] = jx
    except BaseException:
        pass


def parse_density_one_cfg(apps, name, result_dir, count, step):
    times = []
    for j in range(step, count + 1, step):
        lats = []
        for i in range(1, j + 1):
            app = apps[(i - 1) % len(apps)]
            data = get_one_log(f"{result_dir}/density_{name}_{j}_{i}")
            lat = data[app]['times'][-1]
            lat += data[app]['data_restore']
            lats.append(lat)
        times.append(lats)

    mem = []
    with open(f"{result_dir}/{name}_mem_usage") as f:
        lines = f.readlines()
        for line in lines:
            mem.append(int(line))

    data = dict()
    data['times'] = times
    data['mem'] = mem

    return data


def parse_density_logs(result_dir: str):
    with open(f"{result_dir}/apps", "r") as f:
        apps = [app.split('\n')[0] for app in f.readlines()]

    with open(f"{result_dir}/params", "r") as f:
        line = f.readline().split(',')
        count = int(line[0])
        step = int(line[1])

    data = dict()

    for name, _ in DENSITY_CONFIG_SET:
        data[name] = parse_density_one_cfg(apps, name, result_dir, count, step)

    data['x'] = [i for i in range(step, count + 1, step)]
    data['apps'] = apps

    return data


def plot_density_slowdowns(ax, data):
    x_axis = data['x']

    baseline = "same_image"

    all_slowdowns = []
    baseline_times = data[baseline]['times']

    for name, _ in DENSITY_CONFIG_SET:
        if name == baseline:
            continue

        slowdown = []
        for slow, b in zip(data[name]["times"], baseline_times):
            s = 0
            for x, y in zip(slow, b):
                s += float(x / y)
            s /= len(b)
            slowdown.append(s)
        all_slowdowns.append((name, slowdown))

    all_slowdowns = sorted(all_slowdowns, key=lambda s: s[-1])

    for name, slowdown in all_slowdowns:
        ax.plot(x_axis, slowdown, label=name)

    ax.plot(x_axis, [1 for _ in x_axis], label=f"baseline ({baseline})")

    ax.set_xticks(x_axis)
    ax.set_ylabel("Slowdown")
    ax.legend()


def plot_density_mem_usage(ax, data):
    x = data["x"]
    vals = []
    for name, _ in DENSITY_CONFIG_SET:
        d = data[name]
        vals.append((name, [m / (1024**2) for m in d["mem"]]))

    vals = sorted(vals, key=lambda v: v[-1])
    for name, v in vals:
        ax.plot(x, v, label=name)

    ax.set_xticks(x)
    ax.set_ylabel("Memory Usage (MB)")
    ax.legend()


def plot_density(results_dir, data):
    fig, axes = plt.subplots(2, 1)
    plot_density_slowdowns(axes[0], data)
    plot_density_mem_usage(axes[1], data)

    axes[0].set_title(data["apps"])
    plt.xlabel("Concurrent Instances")
    plt.tight_layout()
    plt.savefig(f"{results_dir}/density.pdf")


def parse_microbenchmark_times(result_dir: str):
    from pprint import pprint

    out = defaultdict(dict)

    for tag, name in RESTORE_CONFIG_SET:
        for prog, d in get_one_log(
                f"{result_dir}/restore_images_{tag}").items():
            out[prog][tag] = getstats(d)
        get_kstats(f"{result_dir}/restore_images_{tag}_kstats", out, tag)

    pprint(out)
    return out


def plot_workloads(result_dir: str, data):
    if ARGS.dry_run:
        return

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
                    sm = next(line[0] for line in stack
                              if line[1] == "function")
                else:
                    sm = sum(line[0] for line in stack
                             if line[0] is not None)  # - WARM_ITER
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


def main(tests, name=""):
    if name:
        name = "_" + name
    result_dir = f"{RESULT_DIR}/run.{datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}{name}"
    os.system(f"mkdir -p {result_dir}")
    os.system(f"ln -sfn {result_dir} {RESULT_LINK}")

    if ARGS.redo_snapshot:
        for app in tests:
            app.generate_images(f"{result_dir}/generate_images")

    if ARGS.do_microbench:
        run_microbenchmark(result_dir, tests)
        data = parse_microbenchmark_times(result_dir)
        plot_workloads(result_dir, data)

    if ARGS.do_density:
        kill_iok()
        run_iok(hugepages=False, directpath=True)
        run_density(result_dir, tests, count=ARGS.max_instances, step=2)
        data = parse_density_logs(result_dir)
        plot_density(result_dir, data)

    if ARGS.do_sharing:
        build_loadgen()
        run_sharing(result_dir, tests, count=ARGS.max_instances)
        parse_sharing_logs(result_dir)


def is_running_as_root():
    return os.geteuid() == 0


if __name__ == "__main__":
    if is_running_as_root():
        print("re-run without root")
        exit(-1)
    ARGS = parser.parse_args()
    if ARGS.dirs:
        for d in ARGS.dirs:
            if ARGS.do_microbench:
                data = parse_microbenchmark_times(d)
                plot_workloads(d, data)
            if ARGS.do_density:
                plot_density(d, parse_density_logs(d))
            if ARGS.do_sharing:
                parse_sharing_logs(d)
    else:
        name_regex = re.compile(ARGS.name_filter) if ARGS.name_filter else None
        lang_regex = re.compile(ARGS.lang_filter) if ARGS.lang_filter else None
        arg_name_regex = re.compile(
            ARGS.arg_name_filter) if ARGS.arg_name_filter else None

        def name_filter(test) -> bool:
            return name_regex.search(test.name) if name_regex else True

        def lang_filter(test) -> bool:
            return lang_regex.search(test.lang) if lang_regex else True

        def arg_name_filter(test) -> bool:
            return arg_name_regex.search(
                test.arg_name) if arg_name_regex else True

        def combined_filter(test):
            return name_filter(test) and lang_filter(test) and arg_name_filter(
                test)

        tests = list(filter(combined_filter, TESTS))

        assert len(tests) > 0, "No tests to run!"

        if ARGS.dry_run:
            for test in tests:
                print(test)

        run_iok(directpath=True)
        setup_chroot()
        main(tests)
