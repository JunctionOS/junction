#!/usr/bin/env python

# image resizer code in python
# meant to be a simple test to snapshotting in python
#
# author: bsdinis

import sys
import argparse
import os
import signal
from PIL import Image, ImageChops
from pathlib import Path
from typing import Optional

parser = argparse.ArgumentParser(prog='resizer',
                                 description='A thumbnail generator'
                                 )
parser.add_argument('image', help='filename of the image to resize')
parser.add_argument('reference', help='filename of an already resized image')
parser.add_argument(
    '-v',
    '--verbose',
    help='Verbose logging',
    action='store_true')

MAX_SIZE = (128, 128)


def resize(
        image_path: Path,
        verbose: bool) -> Image.Image:
    if verbose:
        print('[python-resizer]: opening file {}'.format(image_path))

    image = Image.open(image_path)

    image.thumbnail(MAX_SIZE)

    if verbose:
        print('[python-resizer]: resized image')
    return image


def equal_image(a: Image.Image, b: Image.Image, verbose: bool) -> bool:
    if a.size != b.size:
        if verbose:
            print(
                '[python-resizer]: images have different sizes: {}x{} vs {}x{}'.format(
                    a.width,
                    a.height,
                    b.width,
                    b.height))
        return False
    if a.mode != b.mode:
        if verbose:
            print(
                '[python-resizer]: images have different modes: {} vs {}'.format(a.mode, b.mode))
        return False

    a = a.convert('RGB')
    b = b.convert('RGB')
    diff = ImageChops.difference(a, b)

    return not bool(diff.getbbox())


def main():
    args = parser.parse_args()
    image_path = Path(args.image)

    # wait for snapshot
    os.kill(os.getpid(), signal.SIGSTOP)

    thumbnail = resize(image_path, args.verbose)

    thumbnail_path = Path("/tmp/") / image_path.name
    if thumbnail_path.exists():
        thumbnail_path.unlink()

    if args.verbose:
        print(
            '[python-resizer]: saving the thumbnail to {}'.format(thumbnail_path))

    thumbnail.save(thumbnail_path)

    if args.reference:
        if args.verbose:
            print(
                '[python-resizer]: checking the thumbnail is the same as the one in {}'.format(args.reference))
        ref = Image.open(Path(args.reference))
        thumbnail = Image.open(thumbnail_path)

        if equal_image(thumbnail, ref, args.verbose):
            print('OK: thumbnails are the same')
        else:
            print('ERR: thumbnails are not the same')
            exit(-1)


if __name__ == '__main__':
    main()
