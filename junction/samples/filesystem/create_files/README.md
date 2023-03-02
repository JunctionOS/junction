# create_files
This demonstrates `MemFS` functionality in Junction.

When this binary is run without Junction, it won't list any files because `/memfs` is not present on the host filesystem.

However, when running with Junction, it will first populate `/memfs` with some dummy files and then recursively call `getdents` on the directories to show the directory structure of `/memfs`.

## Instructions
`sudo ./build/junction/junction_run ./build/junction/caladan_test.config -- ./build/junction/samples/filesystem/create_files/create_files`
