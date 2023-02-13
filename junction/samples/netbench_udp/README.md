# Netbench UDP
## Junction
### Note
This application requires Caladan to be built with Direcpath and the machine to have an MLX-5 NIC.

### Server
`sudo ./build/junction/junction_run ./build/junction/samples/netbench_udp/caladan_server.config -- ./build/junction/samples/netbench_udp/netbench_udp server`

### Client
`sudo ./build/junction/junction_run ./build/junction/samples/netbench_udp/caladan_client.config -- ./build/junction/samples/netbench_udp/netbench_udp client 7 192.168.127.7 1000 1`

## Linux
### Server
`./build/junction/samples/netbench_udp/netbench_udp server`

### Client
`./build/junction/samples/netbench_udp/netbench_udp client 7 127.0.0.1 1000 1`

