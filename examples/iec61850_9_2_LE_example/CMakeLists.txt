include_directories(
   .
)

set(sv_9_2_LE_example_SRCS
   iec61850_9_2_LE_example.c
   static_model.c
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -mavx2")

SET(CMAKE_EXE_LINKER_FLAGS "-static")   

add_executable(sv_9_2_LE_example
  ${sv_9_2_LE_example_SRCS}
)

target_link_libraries(sv_9_2_LE_example
    iec61850-dpdk
)
