# FunctionBench on Junction
The function will warm up and stop itself. Run junction-ctl to interact with the tracer and send signals. For example,
```
build/junction-ctl/junction-ctl 192.168.230.10
> start-trace 1
> signal 1 SIGCONT
> stop-trace 1
> signal 1 SIGCONT
```

`function_name` can be any of the supported FunctionBench functions. Currently they include:
- `chameleon`
- `float_operation`
- `linpack`
- `matmul`
- `pyaes`
- `image_processing`
- `rnn_serving`
- `json_serdes`
- `video_processing`
- `lr_training`
- `cnn_serving`
