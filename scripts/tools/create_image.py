#!/usr/bin/python3
import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s: %(message)s')

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)

logger.addHandler(ch)

def get_chroot_path(original_path, chroot_root_path):
    """
    Gets the new path starting at the chroot_path.
    """
    return chroot_root_path.rstrip("/") + original_path

def get_mount_points(prefix_path):
    """
    Gets a list of paths that are mounted under the given path as prefix.
    """
    paths = []
    with open('/proc/mounts', 'r') as f:
        lines = f.readlines()
        for line in lines:
            try:
                path = line.strip().split(' ')[1]
                if path.startswith(prefix_path):
                    paths.append(path)
            except:
                continue
    logger.debug(f"Found mountpoints: {paths}")
    return paths

def mount_cmd(src_path, dst_path):
    """
    Mounts the src_path on to dst_path.
    Returns True if successful, False otherwise.
    """
    cmd = ["sudo", "mount", "--bind", src_path, dst_path]
    logger.debug(f"{' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    proc.wait()
    stdout, stderr = proc.communicate()
    if len(stderr) > 0:
        logger.error(f"Failed to mount: {dst_path}")
        logger.error(stderr)
        try:
            os.removedirs(dst_path)
        except Exception as e:
            logger.error(f"Failed to remove: {dst_path}")
        return False
    if proc.returncode != 0:
        logger.error(f"Failed to mount ({proc.returncode}): {dst_path}")
        try:
            os.removedirs(dst_path)
        except Exception as e:
            logger.error(f"Failed to remove: {dst_path}")
        return False
    return True

def umount_cmd(path):
    """
    Unmounts the given path recursively and forecefully.
    Returns True if successful, False otherwise.
    """
    cmd = ["sudo", "umount", "--all-targets", "--recursive", "--force",
            path]
    logger.debug(f"{' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    proc.wait()
    stdout, stderr = proc.communicate()
    if len(stderr) > 0:
        logger.error(f"Failed to umount: {path}")
        logger.error(stderr)
        try:
            os.removedirs(path)
        except Exception as e:
            logger.error(f"Failed to remove: {path}")
        return False
    if proc.returncode != 0:
        logger.error(f"Failed to mount ({proc.returncode}): {path}")
        try:
            os.removedirs(path)
        except Exception as e:
            logger.error(f"Failed to remove: {path}")
        return False
    return True

def rebind_readonly(path):
    """
    Rebinds the given path as read-only.
    Returns True if successful, False otherrwise.
    """
    cmd = ["sudo", "mount", "-o", "bind,remount,ro", path]
    logger.debug(f"{' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    proc.wait()
    stdout, stderr = proc.communicate()
    if len(stderr) > 0:
        logger.error(f"Failed to rebind: {path}")
        logger.error(stderr)
        return False
    if proc.returncode != 0:
        logger.error(f"Failed to rebind: {path}")
        os.remove(chroot_path)
        return False
    return True

def mount(original_path, chroot_root_path, is_file=False):
    """
    Mount the original_path under chroot_root_path.
    e.g., if original_path is /home/abc/def/foo.txt and chroot_root_path is
    /home/xyz then the file foo.txt will be mounted at /home/xyz/abc/def/foo.txt
    Returns the new path if successful, None otherwise.
    """
    chroot_path = get_chroot_path(original_path, chroot_root_path)
    if is_file:
        parent_dir = os.path.dirname(chroot_path)
        os.makedirs(parent_dir, exist_ok=True)
        try:
            Path(chroot_path).touch()
        except Exception as e:
            logger.error(f"Failed to create file: {chroot_path}")
            logger.error(e)
            return None
    else:
        os.makedirs(chroot_path, exist_ok=True)
    if not mount_cmd(original_path, chroot_path):
        return None
    return chroot_path

def get_paths(input_file_path):
    """
    Parses the input file (that is a list of file paths).
    Returns a tuple where the first element is a list of file paths and the
    second element is a list of directory paths that were found in the input
    file and were valid (i.e., the file/directory exists).
    All invalid paths are ignored.
    All returned paths are absolute.
    """
    files = []
    directories = []
    with open(input_file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if os.path.isfile(line):
                files.append(os.path.abspath(line))
            elif os.path.isdir(line):
                directories.append(os.path.abspath(line))
            else:
                logger.warning(f"Invalid path: {line}")
    logger.debug(f"File: {files}")
    logger.debug(f"Directories: {directories}")
    return files, directories

def create_chroot_directory(path):
    """
    Creates a new chroot directory.
    Returns True if successful, False otherwise.
    """
    try:
        os.makedirs(path)
    except FileExistsError as e:
        logger.error(f"chroot path already exists: {path}")
        return False
    return True

def remove_chroot_directory(path):
    """
    Removes the chroot directory (forcefully).
    If there are any mount points under this, they are unmounted forcefully.
    Returns True if successful, False otherwise.
    """
    if not os.path.exists(path):
        return True
    mounted_paths = get_mount_points(path)
    for path in mounted_paths:
        _ = umount_cmd(path)
    try:
        shutil.rmtree(path)
    except FileNotFoundError as e:
        logger.debug(f"chroot path does not exist: {path}")
    return True

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chroot', '-c', type=str, required=True,
                         dest='chroot',
                         help='chroot directory')
    parser.add_argument('--force-remove', '-f', action='store_true',
                         required=False, default=False, dest='force',
                         help='force remove the existing chroot directory')
    parser.add_argument('--input', '-i', type=str, required=False,
                         dest='input', default=None,
                         help='Path to input file containing a list of files to
                               include in the chroot')
    return parser.parse_args()

def main(args):
    chroot_root_path = args.chroot
    force_removal = args.force
    input_file_path = args.input

    if force_removal and not remove_chroot_directory(chroot_root_path):
        sys.exit(1)

    if not input_file_path:
        return

    if not create_chroot_directory(chroot_root_path):
        sys.exit(1)

    files, directories = get_paths(input_file_path)
    mounted_paths = []
    for file in files:
        mounted_path = mount(file, chroot_root_path, is_file=True)
        if mounted_path is not None:
            mounted_paths.append(mounted_path)
    for directory in directories:
        mounted_path = mount(directory, chroot_root_path)
        if mounted_path is not None:
            mounted_paths.append(mounted_path)
    for mounted_path in mounted_paths:
        rebind_readonly(mounted_path)
    
if __name__ == '__main__':
    main(get_args())
