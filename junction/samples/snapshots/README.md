# Snapshot samples for Junction

These are sample programs aimed to be snapshotted with Junction.

## Python

For snapshotting Python, the `python-resizer.py` script uses the Python Image Library ([PIL](https://pypi.org/project/Pillow/)) to create a thumbnail.

Due to Junction limitations, it is not possible to write to the host filesystem.
However, we can pre-run `python-resizer`:

```sh
$ ./python_resizer.py images/<image> [--verbose]
```

Which will write a thumbnail to `thumbnails/<image>`.

Then, we can use junction to check that they are the same:

```sh
# assumes that the iokernel is running somewhere

$ sudo <path_to>/junction_run <path_to>/caladan_test.config -- /usr/bin/python3 <path_to>/python_resizer.py images/<image> -c thumbnails/<image>
```

This will output either `OK: thumbnails are the same` on success or `ERR: thumbnails are not the same` on error.


TODO:
- Integrate with CMake
