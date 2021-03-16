cmake_minimum_required(VERSION 2.8)

# automagically detect if we should cross-compile
if(DEFINED ENV{TOOLCHAIN})
    set(CMAKE_C_COMPILER        $ENV{TOOLCHAIN}gcc)
    set(CMAKE_CXX_COMPILER      $ENV{TOOLCHAIN}g++)
    set(CMAKE_AR        "$ENV{TOOLCHAIN}ar" CACHE FILEPATH "CW archiver" FORCE)
endif()

project(hal-dpdk)

set(LIBHAL_VERSION_MAJOR "2")
set(LIBHAL_VERSION_MINOR "0")
set(LIBHAL_VERSION_PATCH "0")

# feature checks
include(CheckLibraryExists)
check_library_exists(rt clock_gettime "time.h" CONFIG_SYSTEM_HAS_CLOCK_GETTIME)

# check if we are on a little or a big endian
include (TestBigEndian)
test_big_endian(PLATFORM_IS_BIGENDIAN)


include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/inc
)

set (libhal_linux_SRCS
 ${CMAKE_CURRENT_LIST_DIR}/socket/linux/socket_linux.c
 ${CMAKE_CURRENT_LIST_DIR}/ethernet/linux/ethernet_linux.c
 ${CMAKE_CURRENT_LIST_DIR}/thread/linux/thread_linux.c
 ${CMAKE_CURRENT_LIST_DIR}/filesystem/linux/file_provider_linux.c
 ${CMAKE_CURRENT_LIST_DIR}/time/unix/time.c
 ${CMAKE_CURRENT_LIST_DIR}/serial/linux/serial_port_linux.c
 ${CMAKE_CURRENT_LIST_DIR}/memory/lib_memory.c
)

set (libhal_SRCS
    ${libhal_linux_SRCS}
)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -mavx2")
SET(CMAKE_EXE_LINKER_FLAGS "-static")

add_library (hal-dpdk STATIC ${libhal_SRCS})

add_library (hal-dpdk-shared STATIC ${libhal_SRCS})

target_compile_definitions(hal-dpdk-shared PRIVATE EXPORT_FUNCTIONS_FOR_DLL)

SET_TARGET_PROPERTIES(hal-dpdk-shared PROPERTIES
  COMPILE_FLAGS "-fPIC"
)

SET(DPDK_LIBS
	rte_net      rte_ethdev       rte_distributor 	 rte_mbuf      rte_pmd_bond       rte_kni              rte_pmd_ring     
	rte_acl      rte_eal          rte_kvargs   	 rte_mempool   rte_mempool_ring	  rte_pmd_e1000        rte_pmd_virtio   rte_ring
	rte_cfgfile  rte_hash         rte_lpm      	 rte_meter     rte_pmd_i40e   	  rte_sched        rte_timer
	rte_cmdline  rte_ip_frag      rte_pipeline 	 rte_pmd_ixgbe rte_mempool_stack  rte_table        rte_pmd_bnxt
	rte_pmd_ena  rte_pmd_nfp      rte_stack          rte_bus_vdev  rte_bus_pci        rte_pci              rte_cryptodev
)

target_link_libraries (hal-dpdk
  -Wl,--whole-archive -Wl,--start-group ${DPDK_LIBS} -Wl,--end-group -Wl,--no-whole-archive
  -ldl
  -lnuma
  -lpthread
  -lrt
)

set(BINDIR "bin")
set(LIBDIR "lib")

include(GNUInstallDirs)
set(LIBDIR ${CMAKE_INSTALL_LIBDIR})
set(BINDIR ${CMAKE_INSTALL_BINDIR})


install (TARGETS hal-dpdk hal-dpdk-shared
	RUNTIME DESTINATION ${BINDIR} COMPONENT Applications
	ARCHIVE DESTINATION ${LIBDIR} COMPONENT Libraries
    LIBRARY DESTINATION ${LIBDIR} COMPONENT Libraries
)
