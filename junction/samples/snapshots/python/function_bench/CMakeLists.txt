message(STATUS "setting up function bench tests")

set(tests
    "chameleon"
    "float_operation"
    "image_processing"
    "json_serdes"
    "linpack"
    "lr_training"
    "matmul"
    "pyaes"
    "rnn_serving"
    # "video_processing" - slow.
    # cnn_serving
)

set(venv_python
  "${CMAKE_SOURCE_DIR}/bin/venv/bin/python3"
)

foreach(f IN ITEMS ${CMAKE_CURRENT_SOURCE_DIR}/)
    file(COPY ${f} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()

execute_process(COMMAND ${CMAKE_SOURCE_DIR}/bin/venv/bin/python3 -m grpc_tools.protoc -I=${CMAKE_CURRENT_BINARY_DIR} --python_out=${CMAKE_CURRENT_BINARY_DIR} --grpc_python_out=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/helloworld.proto)

set(fb_run
  "${CMAKE_CURRENT_BINARY_DIR}/run.py"
)

foreach(test ${tests})
  add_snapshot_restore_test(function_bench_${test} "${venv_python} ${fb_run} ${test}")
endforeach()
