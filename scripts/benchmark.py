#!/usr/bin/python3

import os
import sys
from datetime import datetime
import json
import subprocess
import time

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.split(os.path.realpath(__file__))[0]
ROOT_DIR = f"{SCRIPT_DIR}/.."
BUILD_DIR = f"{ROOT_DIR}/build"
JRUN = f"{BUILD_DIR}/junction/junction_run"
CONFIG = f"{BUILD_DIR}/junction/caladan_test.config"
CALADAN_DIR = f"{ROOT_DIR}/lib/caladan"

FBENCH = ["chameleon", "float_operation", "pyaes", "matmul"] + ["video_processing", "lr_training", "image_processing", "linpack","json_serdes", "rnn_serving"]
RESIZERS = ["java_resizer", "rust_resizer", "go_resizer", "python_resizer"]
OTHERS = ["go_hello_world", "node_hello", "python_numpy", "python_hello_world"]

def run(cmd):
	print(cmd)
	sys.stdout.flush()
	subprocess.check_output(cmd, shell=True)

def kill_iok():
	run("sudo pkill iokerneld || true")

def run_iok():
	if os.system("pgrep iok > /dev/null") == 0:
		return
	run(f"sudo {CALADAN_DIR}/scripts/setup_machine.sh")
	run(f"sudo {CALADAN_DIR}/iokerneld ias nobw noht no_hw_qdel numanode -1 -- --allow 00:00.0 --vdev=net_tap0 > /tmp/iokernel.log 2>&1 &")
	while os.system("grep -q 'running dataplan' /tmp/iokernel.log") != 0:
		time.sleep(0.3)
		run("pgrep iokerneld > /dev/null")

def snapshot_elf(cmd, output_image, output_log, extra_flags = "", stop_count = 1):
	run(f"{JRUN} {CONFIG} {extra_flags} -S {stop_count} --snapshot-prefix {output_image} -- {cmd} 2>&1 >> {output_log}_snapelf")

def snapshot_jif(cmd, output_image, output_log, extra_flags = "", stop_count = 1):
	run(f"{JRUN} {CONFIG} {extra_flags} --jif -S {stop_count} --snapshot-prefix {output_image} -- {cmd} 2>&1 >> {output_log}_snapjif")

def restore_elf(image, output_log, extra_flags = ""):
	run(f"{JRUN} {CONFIG} {extra_flags} -r -- {image}.metadata {image}.elf 2>&1 >> {output_log}_elf")

def process_itree(output_image, output_log):
	run(f"{BUILD_DIR}/jiftool {output_image}.jif {output_image}_itrees.jif 2>&1 >> {output_log}_builditree")

def restore_jif(image, output_log, extra_flags = ""):
	run(f"{JRUN} {CONFIG} {extra_flags} --jif -r -- {image}.jm {image}.jif 2>&1 >> {output_log}_jif")

def restore_itrees_jif(image, output_log, extra_flags = ""):
	run(f"{JRUN} {CONFIG} {extra_flags} --jif -r -- {image}.jm {image}_itrees.jif 2>&1 >> {output_log}_itrees_jif")

def generate_images(cmd, name, logname, stop_count = 1):
	snapshot_elf(cmd, name, logname, "", stop_count)
	snapshot_jif(cmd, name, logname, "", stop_count)
	process_itree(name, logname)

def dropcache():
	for i in range(3):
		run("echo 3 | sudo tee /proc/sys/vm/drop_caches")
		time.sleep(0.3)

def restore_image(name, logname, extra_flags=""):
	dropcache()
	restore_elf(name, logname, extra_flags)
	dropcache()
	restore_jif(name, logname, extra_flags)
	dropcache()
	restore_itrees_jif(name, logname, extra_flags)

def get_fbench_times(edir):

	for fn in FBENCH:
		generate_images(f"{ROOT_DIR}/bin/venv/bin/python3 {ROOT_DIR}/junction/samples/snapshots/python/function_bench/run.py {fn}", f"{edir}/{fn}", f"{edir}/generate_images")
		restore_image(f"{edir}/{fn}", f"{edir}/restore_images")

def get_one_log(name):
	try:
		with open(name) as x:
			dat = x.read().splitlines()
	except:
		return None

	progs = {}
	prev_restore = None
	for l in dat:
		if "DATA  " not in l:
			if "restore time" in l:
				prev_restore = l
			continue
		lx = l.split("DATA  ")[-1].strip()
		xx = json.loads(lx)
		assert xx['program'] not in progs, xx

		if prev_restore:
			l = prev_restore.split("restore time")[1].split()
			xx["metadata_restore"] = int(l[2])
			xx["data_restore"] = int(l[4])
			prev_restore = None

		progs[xx["program"]] = xx

	return progs

def parse_fbench_times(edir):
	from pprint import pprint

	out = {}
	for prog, d in get_one_log(f"{edir}/restore_images_elf").items():
		out[prog] = {
			'first_iter': d['warmup'][0],
			'warm_iter': d['warmup'][-1],
			'metadata_restore': d["metadata_restore"],
			'elf_first_iter': d["cold"][0],
			'elf_data_restore': d["data_restore"]
		}

	for prog, d in get_one_log(f"{edir}/restore_images_jif").items():
		out[prog]['jif_cold_first_iter'] = d["cold"][0]
		out[prog]['jif_data_restore'] = d["data_restore"]

	for prog, d in get_one_log(f"{edir}/restore_images_itrees_jif").items():
		out[prog]['itrees_jif_cold_first_iter'] = d["cold"][0]
		out[prog]['itrees_jif_data_restore'] = d["data_restore"]

	pprint(out)
	return out

def plot_workloads(edir, data):
	workloads = list(data.keys())
	num_workloads = len(workloads)
	fig, axes = plt.subplots(num_workloads, 1, figsize=(10, 5 * num_workloads))

	if num_workloads == 1:
		axes = [axes]

	colors = {
		'metadata_restore': 'tab:blue',
		'elf_data_restore': 'tab:orange',
		'elf_first_iter': 'tab:green',
		'jif_data_restore': 'tab:red',
		'jif_cold_first_iter': 'tab:purple',
		'warm_iter': 'tab:gray'
	}

	for ax, workload in zip(axes, workloads):
		categories = data[workload]
		warm_iter = categories['warm_iter']

		metadata_restore = categories['metadata_restore']
		elf_data_restore = categories['elf_data_restore']
		elf_first_iter = categories['elf_first_iter']

		jif_data_restore = categories['jif_data_restore']
		jif_cold_first_iter = categories['jif_cold_first_iter']

		# Creating stacks
		stack1 = [metadata_restore, elf_data_restore, elf_first_iter]
		stack2 = [metadata_restore, jif_data_restore, jif_cold_first_iter]

		# Plotting warm_iter
		ax.bar('warm_iter', warm_iter, color=colors['warm_iter'], label='Warm Iter')

		seen = set()

		def get_lbl(label):
			if label in seen: return None
			seen.add(label)
			return label

		# Plotting stack1
		bottom_stack1 = 0
		for component, label in zip(stack1, ['metadata_restore', 'elf_data_restore', 'elf_first_iter']):
			ax.bar('ELF', component, bottom=bottom_stack1, color=colors[label], label=get_lbl(label))
			bottom_stack1 += component

		# Plotting stack2
		bottom_stack2 = 0
		for component, label in zip(stack2, ['metadata_restore', 'jif_data_restore', 'jif_cold_first_iter']):
			ax.bar('JIF', component, bottom=bottom_stack2, color=colors[label], label=get_lbl(label))
			bottom_stack2 += component
		ax.set_title(workload)
		ax.legend()

	plt.tight_layout()
	plt.savefig(f'{edir}/graph.pdf', bbox_inches='tight')

def main():
	name = ""
	name = f"run.{datetime.now().strftime('%Y%m%d%H%M%S')}{name}"
	os.system(f"mkdir {name}")
	get_fbench_times(name)
	data = parse_fbench_times(name)
	plot_workloads(name, data)

if __name__ == '__main__':
	if len(sys.argv) > 1:
		for d in sys.argv[1:]:
			plot_workloads(d, parse_fbench_times(d))
	else:
		run_iok()
		main()
