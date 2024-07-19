#!/usr/bin/env python3

import argparse
import matplotlib.pyplot as plt
import pathlib
import subprocess
import sys

def get_data_size(filename, readjif_path) -> int:
    # run readjif <filename> jif.private_pages
    result = subprocess.run([readjif_path, filename, "jif.private_pages"], capture_output=True)
    if result.returncode != 0:
        raise ChildProcessError("failed to run readjif")

    output = result.stdout.decode('utf-8')
    pages = output.strip().split(':')[1].split(',')[0].strip()
    return int(pages)

def get_stats(dir1, dir2, readjif_path):
    dir1_files = { p.name: p for p in dir1.glob('*.jif') }

    dir2_files = { p.name: p for p in dir2.glob('*.jif') }

    intersection = set(dir1_files.keys()).intersection(set(dir2_files.keys()))

    xs = []
    ys = []
    relative = []
    names = []
    for name in intersection:
        path1 = dir1_files[name]
        path2 = dir2_files[name]

        x = get_data_size(path1, readjif_path)
        y = get_data_size(path2, readjif_path)

        xs.append(x)
        ys.append(y)
        relative.append((y * 100.0) / x)
        names.append(name)

    return (names, xs, ys, relative)

def dump_stats(values):
    values = sorted(zip(values[0], values[1], values[2], values[3]), key=lambda x: x[1])
    print('{:50}| Orig N pages | Compressed N pages |  Ratio'.format('Filename'))
    for (name, orig, new, relative) in values:
        print('{:50}| {:12} | {:18} | {:6.2f}%'.format(name, orig, new, relative))

def plot(values, relative: bool, output_filename):
    plt.scatter(values[1], values[3] if relative else values[2])
    plt.xlabel('Original Size (#pages)')
    if relative:
        plt.ylabel('Compression Rate (%)')
    else:
        plt.ylabel('Compressed Size (#pages)')

    plt.title('ITree impact on private data size')
    plt.savefig(output_filename)

if __name__ == '__main__':
    import os

    parser = argparse.ArgumentParser(prog='plot the effects of compression')
    parser.add_argument('orig', type=pathlib.Path, help='the directory of what will be considered the _original_ JIF files')
    parser.add_argument('new', type=pathlib.Path, help='the directory of what will be considered the _new_ JIF files')
    parser.add_argument('output', type=pathlib.Path, help='the file to dump the plot in')
    parser.add_argument('--relative', action='store_true', help='whether to use relative or absolute comparison')

    args = parser.parse_args()

    pwd = pathlib.Path(__file__).absolute()
    junction_dir = pwd / '..' / '..' / '..'
    readjif_path = junction_dir / 'build' / 'readjif'

    values = get_stats(args.orig, args.new, readjif_path.resolve())
    dump_stats(values)
    plot(values, args.relative, args.output)
