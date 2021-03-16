
set(goose_subscriber_example_SRCS
   goose_subscriber_example.c
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -mavx2")

SET(CMAKE_EXE_LINKER_FLAGS "-static")   
                                       
add_executable(goose_subscriber_example
  ${goose_subscriber_example_SRCS}
)

target_link_libraries(goose_subscriber_example
    iec61850-dpdk
)


