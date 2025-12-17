# Serverless

A simple implementation of a mock FaaS.

## Junction

### Prepare

In order to simulate this experiment, it requires two separate machine that can talk within a private IP address (e.g. two nodes in a CloudLab experiment).

Make sure you have built junction using `scripts/build.sh` and the scheduler is running. The scheduler should be bound to the NIC which is setup for the private IP communication. You may need to set the status of the NIC to DOWN to do this.

### Gateway

This will run the gateway.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_gateway.config --function_name gateway --keep_alive -- ./samples/serverless/gateway
```

### Function

Open a new terminal and follow these steps.

This will warmup the function.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_function.config --function_name function_warmup --function_arg warmup_data -- ./samples/serverless/function
```

After the warmup completes, run in restored mode to continue from the main function. We will set the `keep_alive` flag to keep the channel alive to listen for client requests.

```bash
./junction_run ./samples/serverless/caladan_function.config --restore --function_name function --function_arg restore --keep_alive -- .metadata .elf
```

The function is able to get or add users. The valid requests are `GET /user/{id}` and `POST /user {name}`.  
You should see the server response if it was successful.

### Client

From a different machine, you can simply create a TCP connection with the gateway by using tools like netcat.

```bash
nc -v <gateway IP> 8080
GET /user/0

nc -v <gateway IP> 8080
POST /user/ <name>
```

### Client (Junction Instance)

Only run this if you would like to run the client as a junction instance and directly communicate with the function channel.

Open a new terminal and send request directly to the serverless channel.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_client.config -- ./samples/serverless/client "GET /user/0"
```

