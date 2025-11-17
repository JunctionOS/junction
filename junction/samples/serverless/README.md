# Serverless

A simple implementation of a mock FaaS.

## Junction

### Prepare

Make sure you have built junction using `scripts/build.sh` and the scheduler is running.

### Function

This will warmup the function.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_function.config --function_name function_warmup --function_arg warmup_data -- ./samples/serverless/function
```

After the warmup completes, run in restored mode to continue from the main function. We will set the `keep_alive` flag to keep the channel alive to listen for client requests.

```bash
./junction_run ./samples/serverless/caladan_function.config --restore --function_name function --function_arg restore --keep_alive -- .metadata .elf
```

### Client

Open a new terminal and send request to the serverless channel.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_client.config -- ./samples/serverless/client "GET /user/0"
```

The server is able to get or add users. The valid requests are "GET /user/{id}" and "POST /user {name}".  
You should see the server response if it was successful.
