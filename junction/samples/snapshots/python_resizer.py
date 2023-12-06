#!/usr/bin/env python

# image resizer code in python
# meant to be a simple test to snapshotting in python
#
# author: bsdinis

import sys
import argparse
from PIL import Image, ImageChops
from pathlib import Path
from typing import Optional

parser = argparse.ArgumentParser(prog='resizer',
                                 description='A thumbnail generator'
                                 )
parser.add_argument('image', help='filename of the image to resize')
parser.add_argument(
    '-c',
    '--check',
    help='Check that the thumbnail generated is the same as the one in the file provided')
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

    return diff.getbbox()


def main():
    args = parser.parse_args()
    image_path = Path(args.image)

    thumbnail = resize(image_path, args.verbose)

    if args.check:
        if args.verbose:
            print(
                '[python-resizer]: checking the thumbnail is the same as the one in {}'.format(args.check))
        input_thumbnail = Image.open(Path(args.check))

        if equal_image(thumbnail, input_thumbnail, args.verbose):
            print('OK: thumbnails are the same')
        else:
            print('ERR: thumbnails are not the same')
    else:
        image_name = image_path.name
        image_parent = image_path.parents[1]
        thumbnail_path = image_parent / 'thumbnails' / image_name
        if args.verbose:
            print(
                '[python-resizer]: saving the thumbnail to {}'.format(thumbnail_path))

        thumbnail.save(thumbnail_path)


if __name__ == '__main__':
    main()
