#!/usr/bin/env python3

import argparse
import matplotlib.pyplot as plt
import pathlib
import random
import subprocess
import sys

def get_itree_sizes(filename, readjif_path):
    # run readjif <filename> pheader.n_itree_nodes
    result = subprocess.run([readjif_path, filename, "pheader.n_itree_nodes"], capture_output=True)
    if result.returncode != 0:
        raise ChildProcessError("failed to run readjif")

    output = result.stdout.decode('utf-8')
    n_nodes = list()
    for line in output.strip().split('\n'):
        if '[' in line or ']' in line: continue
        n_nodes.append(int(line.strip().split(':')[1].split(',')[0].strip()))

    return n_nodes

def get_stats(direc, readjif_path):
    return sum((get_itree_sizes(filename, readjif_path) for filename in direc.glob('*.jif')), [])

def plot(values, output_filename):
    plt.boxplot(values, vert=False)

    ys = [ (random.random() - 0.5) * .05 + 1.0 for _ in values ]
    plt.scatter(values, ys, alpha=0.05, color='green')

    plt.ylabel('ITree size in # nodes')
    plt.savefig(output_filename)

if __name__ == '__main__':
    import os

    parser = argparse.ArgumentParser(prog='plot the effects of compression')
    parser.add_argument('directory', type=pathlib.Path, help='directory to analyze')
    parser.add_argument('output', type=pathlib.Path, help='the file to dump the plot in')

    args = parser.parse_args()

    pwd = pathlib.Path(__file__).absolute()
    junction_dir = pwd / '..' / '..' / '..'
    readjif_path = junction_dir / 'build' / 'readjif'

    values = sorted(get_stats(args.directory, readjif_path.resolve()))
    print('median itree size: {}'.format(values[len(values) // 2]))
    print('max    itree size: {}'.format(values[-1]))
    plot(values, args.output)
