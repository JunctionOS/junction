#!/usr/bin/env python3

import argparse
import matplotlib.pyplot as plt
import pathlib
import random
import subprocess
import sys

FANOUT=4

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

    return (filename.name,  sorted(n_nodes))

def get_stats(direc, readjif_path):
    aggregated = [get_itree_sizes(filename, readjif_path) for filename in direc.glob('*.jif')]
    aggregated = sorted(aggregated, key=lambda x: x[0])
    aggregated = [('Total', sorted(sum(map(lambda x: x[1], aggregated), [])))] + aggregated
    return aggregated

def print_stats(stats):
    for name, values in stats[1:]:
        print('{:50} | p25={:4} | median={:4} | p75={:4} | p99={:4} | max={:4}'.format(name, values[len(values) // 4], values[len(values) // 2], values[(3 * len(values)) // 4], values[(99 * len(values)) // 100], values[-1]))

    for name, values in stats[:1]:
        print('{:50} | p25={:4} | median={:4} | p75={:4} | p99={:4} | max={:4}'.format(name, values[len(values) // 4], values[len(values) // 2], values[(3 * len(values)) // 4], values[(99 * len(values)) // 100], values[-1]))

def box_plot(stats, output_filename):
    plt.boxplot([v for _, v in stats], showfliers=False, vert=False)

    for idx, (_, v) in enumerate(stats):
        ys = [ (random.random() - 0.5) * .1 + (idx + 1.0) for _ in v ]
        plt.scatter(v, ys, alpha=0.05, color='red' if idx == 0 else 'green')

    plt.xlabel('ITree size in # nodes')

def violin_plot(stats):
    color_idx = lambda idx: 'red' if idx == 0 else 'green'
    parts = plt.violinplot([v for _, v in stats], vert=False)
    for idx, pc in enumerate(parts['bodies']):
        pc.set_color(color_idx(idx))

    parts['cmins'].set_alpha(0.9)
    parts['cmaxes'].set_alpha(0.9)
    parts['cbars'].set_alpha(0.9)
    parts['cmins'].set_color([color_idx(idx) for idx in range(len(stats))])
    parts['cmaxes'].set_color([color_idx(idx) for idx in range(len(stats))])
    parts['cbars'].set_color([color_idx(idx) for idx in range(len(stats))])

if __name__ == '__main__':
    import os

    parser = argparse.ArgumentParser(prog='plot the effects of compression')
    parser.add_argument('directory', type=pathlib.Path, help='directory to analyze')
    parser.add_argument('output', type=pathlib.Path, help='the file to dump the plot in')
    parser.add_argument('--total', action='store_true', help='whether to show only the total distribution')

    args = parser.parse_args()

    pwd = pathlib.Path(__file__).absolute()
    junction_dir = pwd / '..' / '..' / '..'
    readjif_path = junction_dir / 'build' / 'readjif'

    stats = get_stats(args.directory, readjif_path.resolve())
    print_stats(stats)

    max_val = max(stats[0][1])
    if args.total:
        stats = stats[:1]

    if len(stats) > 4:
        figure = plt.figure()
        figure.set_figheight(figure.get_figheight() * (len(stats) / 6))
        figure.set_figwidth(figure.get_figwidth() * 2)

    violin_plot(stats)

    depth = 0
    plt.axvline(0, alpha=0.5, lw=0.5)
    while FANOUT ** depth < max_val:
        plt.axvline(FANOUT ** depth, alpha=0.5, lw=0.5)
        depth += 1

    plt.yticks(range(1, len(stats)+1), [name for name, _ in stats])
    plt.tight_layout()
    plt.savefig(args.output)
