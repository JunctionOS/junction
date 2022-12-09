# TCP
## Junction
### Note
This application requires Caladan to be built with Direcpath and the machine to have an MLX-5 NIC.

### Server
`sudo ./build/junction/junction_run ./build/junction/samples/tcp/caladan_server.config -- ./build/server 4096 10000`

### Client
`sudo ./build/junction/junction_run ./build/junction/samples/tcp/caladan_client.config -- ./build/client 4096 10000 192.168.127.7`

## Linux
### Server
`./build/server 4096 10000`

### Client
`./build/client 4096 10000 127.0.0.1`

