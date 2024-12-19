# Junction

Junction is a prototype for a next generation datacenter operating system that focuses on improving performance and security while enabling high degrees of resource multiplexing.

Junction moves most OS functionality into userspace with a library operating system (LibOS) that uses kernel-bypass CPU features and network queues for high performance. The host kernel plays a minimal role - it is only responsible for multiplexing CPU cores, memory, and the page cache. This reduces the wide attack surface posed by the system call interfaces in today's OSes.

Applications run in Junction containers, each of which has a private copy of the Junction LibOS shared by the applications in the container. Our prototype LibOS implements a large fraction of the Linux system call interface, and can run unmodified Linux binaries. Junction is able to run programs written in Python, Javascript, Java, and Go, and many written in C/C++/Rust.

Our [paper](https://www.usenix.org/conference/nsdi24/presentation/fried) on Junction appeared at NSDI 2024 and describes our motivation and design in greater detail.

### Contributing

We welcome contributions to Junction. If you have an issue with missing functionality or other bugs, please let us know and feel free to submit a pull request!

### Contact

For any questions about Junction, please email <junction@csail.mit.edu> or open an issue on Github.

## Hardware Requirements

Junction runs on modern x86 Intel and AMD CPUs. For optimal networking performance, Junction requires
a modern NVIDIA NIC (ConnectX-5 and later). Junction can also support other NICs using a DPDK SoftNIC with reduced performance, security, and density guarantees. 

Junction supports User IPIs (UIPIs) for increased security and better interrupt performance. UIPI is available on Intel server processors starting with 4th Generation Xeon Scalable CPUs (codenamed Sapphire Rapids). For other CPUs, Junction automatically uses Linux signals.

## Software Requirements

Junction runs on unmodified Linux Kernels, and was tested on versions 6.2.0 and later. Building Junction requires GCC 12 or later. Our scripts assume your machine is using Ubuntu, though Junction itself can run on other distros.

## Building Junction
Clone the Junction repo and run the following script that installs needed packages (using apt) and builds dependencies. This step can take a few minutes.
```
scripts/install.sh
```

Install rust.
```
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=nightly
```

Next, run the following command to compile Junction itself.
```
scripts/build.sh
```

## Running Junction

In order to run Junction, the core scheduler must be running. Run the following command in a seperate window:
```
sudo lib/caladan/scripts/setup_machine.sh
sudo lib/caladan/iokerneld ias
```
Note that the arguments that you provide to the core scheduler will vary depending on your network configuration (see [networking](#Networking-Options)).

You can start a Junction container using `junction_run`. Each Junction container is started with a configuration file that specifies the maximum number of cores to use and a unique IP address. A sample configuration file is provided at `build/junction/caladan_test.config`. To run a program, simply pass that program and its arguments to `junction_run` as follows:

```
cd build/junction
./junction_run caladan_test.config -- /usr/bin/openssl speed
```

To run multiple applications inside a single Junction container, we recommend using a shell script that launches each application. We found that Junction works with the [fish shell](https://github.com/fish-shell/fish-shell) which uses `posix_spawn()` instead of `fork()`.

## Networking Options

### ConnectX NICs
This networking mode provides the best security, density, and performance for Junction. It requires a dedicated NVIDIA ConnectX-5 or later NIC.

You will need the PCI address of your NIC, which can be found by running `lspci | grep ConnectX`.
If an interface is configured in Linux for this NIC, you will first need to bring it down by running `sudo ip link set down <ifname>`.

Next, bind the NIC to the vfio driver:
```
sudo modprobe vfio-pci
sudo lib/caladan/dpdk/usertools/dpdk-devbind.py -b vfio-pci <pci address>
```

Finally, use the following command when starting the core scheduler:
```
sudo lib/caladan/iokerneld ias vfio nicpci <pci address>
```

### DPDK SoftNIC
If your machine has a high performance NIC that works with DPDK, you may use that instead. We have tested support for Intel NICs that use the ixgbe and i40e drivers.

Use the following command to launch the core scheduler:
```
sudo lib/caladan/iokerneld ias no_hw_qdel nicpci <pci address>
```

### No High Performance NIC (TUN/TAP)
When a high performance networking is not needed, the DPDK SoftNIC can be configured to use a TUN/TAP device. Start the core scheduler with this command:
```
sudo lib/caladan/iokerneld ias no_hw_qdel -- --allow 00:00.0 --vdev=net_tap0
```

## Configuring Preemption
The scheduler time slice quantum can be set on a per-container basis by appending `runtime_quantum_us <us>` to the configuration file used to launch the container. If User IPIs are available on your [machine](#Hardware-Requirements), they will be enabled automatically. To force the use of Linux signals instead, add `nouintr` as an argument when running the `setup_machine.sh` script (see [Running Junction](#Running-Junction)). Note that all Junction containers and the scheduler must be closed when running this script.

## Testing
You can run a suite of unit and end-to-end tests using the following script:
```
scripts/test.sh
```

## Debugging
Junction can be built in debug mode by adding the `-d` flag to the build script.
When using GDB to debug, it may be necessary to manually load the symbols for programs loaded by Junction.
To quickly add these symbols, you can run `source <path to junction>/scripts/tools/gdb_find_symbols.py` in GDB after the program and its shared libraries are loaded.


## License
See the [LICENSE](LICENSE.md) file for license rights and limitations (MIT).
