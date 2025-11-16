# Serverless

## Junction

### Function

This will warmup the serverless function.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_function.config --function_name sample --function_arg warmup_data -- ./samples/serverless/function
```

After the warmup completes, run in restored mode to continue from the main function.

```bash
./junction_run ./samples/serverless/caladan_function.config --restore --function_name sample --function_arg restore -- .metadata .elf
```

### Client

Open a new terminal and send request to the serverless channel.

```bash
cd ./build/junction
./junction_run ./samples/serverless/caladan_client.config -- ./samples/serverless/client "GET /user/0"
```

The server is able to get or add users. The valid requests are "GET /user/{id}" and "POST /user {name}".

You should see the server response if it was successful.
