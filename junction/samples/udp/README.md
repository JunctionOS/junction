# UDP
## Junction
### Note
This application requires Caladan to be built with Direcpath and the machine to have an MLX-5 NIC.

### Server
`sudo ./build/junction/junction_run ./build/junction/samples/udp/caladan_server.config -- ./build/junction/samples/udp/udp_server 1024 5000`

### Client
`sudo ./build/junction/junction_run ./build/junction/samples/udp/caladan_client.config -- ./build/junction/samples/udp/udp_client 1024 5000 192.168.127.3`

## Linux
### Server
`./build/junction/samples/udp/udp_server 1024 5000`

### Client
`./build/junction/samples/udp/udp_client 1024 5000 127.0.0.1`

