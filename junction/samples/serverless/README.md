# Serverless

A simple implementation of a mock FaaS.

## Junction

### Prepare

In order to simulate this experiment, it requires two separate machine that can talk within a private IP address (e.g. two nodes in a CloudLab experiment).

Make sure you have built junction, and the scheduler is running, as described in the main README file. The scheduler should be bound to the NIC which is setup for the private IP communication. You may need to set the status of the NIC to DOWN to do this.

### Gateway

This will run the gateway.

```bash
cd ./build/junction
```

```bash
./junction_run ./samples/serverless/caladan_gateway.config --function_name gateway --keep_alive -- ./samples/serverless/gateway
```

### Functions

There are two services, `user_service` and `follower_service`.

For each service, open a new terminal and follow these steps to start a junction instance.

Go to build directory.

```bash
cd ./build/junction
```

These steps will warmup the function:

#### Warmup user_service

```bash
./junction_run ./samples/serverless/caladan_user_service.config --function_name user --function_arg warmup_data --snapshot-prefix user -- ./samples/serverless/user_service
```

#### Warmup follower_service

```bash
./junction_run ./samples/serverless/caladan_follower_service.config --function_name follower --function_arg warmup_data --snapshot-prefix follower -- ./samples/serverless/follower_service
```

After the warmup completes, run in restored mode to continue from the main function. We will set the `keep_alive` flag to keep the channel alive to listen for client requests.

#### Restore user_service

```bash
./junction_run ./samples/serverless/caladan_user_service.config --restore --function_name user --function_arg restore --keep_alive -- user.metadata user.elf
```

#### Restore follower_service

```bash
./junction_run ./samples/serverless/caladan_follower_service.config --restore --function_name follower --function_arg restore  --keep_alive -- follower.metadata follower.elf
```

The `user_service` is able to get or add users. The valid requests are `GET /user/{id}` and `POST /user {name}`.

The `follower_service` is able to get all followers for a certain user id with `GET /followers/{id}`.

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
