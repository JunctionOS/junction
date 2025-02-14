message(STATUS "Building junction control server")

set(SOURCES_C_CPP
  serverless.cc
  webctl.cc
)

set(FLATBUFFER_SCHEMA_FILES
  control_request.fbs
  control_response.fbs
)
set(FLATBUFFER_GENERATED_CPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(FLATBUFFER_GENERATED_RS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../junction-ctl/src")

function(compile_flatbuffers flatbuffers_schemas
                           custom_target_name
                           lang_flag
                           generated_includes_dir
                           suffix)

  # Test if including from FindFlatBuffers
  if(FLATBUFFERS_FLATC_EXECUTABLE)
    set(FLATC_TARGET "")
    set(FLATC ${FLATBUFFERS_FLATC_EXECUTABLE})
  elseif(TARGET flatbuffers::flatc)
    set(FLATC_TARGET flatbuffers::flatc)
    set(FLATC flatbuffers::flatc)
  else()
    set(FLATC_TARGET flatc)
    set(FLATC flatc)
  endif()
  set(FLATC_SCHEMA_ARGS --gen-mutable)
  if(FLATBUFFERS_FLATC_SCHEMA_EXTRA_ARGS)
    set(FLATC_SCHEMA_ARGS
      ${FLATBUFFERS_FLATC_SCHEMA_EXTRA_ARGS}
      ${FLATC_SCHEMA_ARGS}
      )
  endif()

  # Generate the include files parameters.
  set(all_generated_files "")

  foreach(schema ${flatbuffers_schemas})
    get_filename_component(filename ${schema} NAME_WE)
    # For each schema, do the things we requested.
    set(generated_include ${generated_includes_dir}/${filename}_generated.${suffix})
    add_custom_command(
      OUTPUT ${generated_include}
      COMMAND ${FLATC} ${FLATC_SCHEMA_ARGS}
      -o ${generated_includes_dir}
      ${lang_flag} ${CMAKE_CURRENT_SOURCE_DIR}/${schema}
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${schema}
      WORKING_DIRECTORY "${working_dir}")
    list(APPEND all_generated_files ${generated_include})
  endforeach()

  # Create a custom target that depends on all the generated files.
  # This is the target that you can depend on to trigger all these
  # to be built.
  add_custom_target(${custom_target_name}
                    DEPENDS ${all_generated_files})
endfunction()


compile_flatbuffers("${FLATBUFFER_SCHEMA_FILES}"
    control_schema_cpp
    "--cpp"
    "${FLATBUFFER_GENERATED_CPP_INCLUDE_DIR}"
    h
)

compile_flatbuffers("${FLATBUFFER_SCHEMA_FILES}"
    control_schema_rs
    "--rust"
    "${FLATBUFFER_GENERATED_RS_INCLUDE_DIR}"
    rs
)

add_library(control_fbs INTERFACE)
target_include_directories(control_fbs INTERFACE
    ${FLATBUFFERS_INCLUDE_DIR}
    )
add_dependencies(control_fbs control_schema_cpp control_schema_rs)

add_library(control_c_cpp OBJECT ${SOURCES_C_CPP})
add_dependencies(control_c_cpp control_schema_cpp control_schema_rs)

add_library(control STATIC
  $<TARGET_OBJECTS:control_c_cpp>
)
