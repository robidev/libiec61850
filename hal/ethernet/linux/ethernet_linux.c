/*
 *  ethernet_linux.c
 *
 *  Copyright 2013 Michael Zillgith
 *
 *  This file is part of libIEC61850.
 *
 *  libIEC61850 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libIEC61850 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libIEC61850.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  See COPYING file for the complete license text.
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include <string.h>

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>


#include "lib_memory.h"
#include "hal_ethernet.h"

#ifndef DEBUG_SOCKET
#define DEBUG_SOCKET 0
#endif

struct rte_mempool *mbuf_pool;

struct rte_ether_addr rte_addr;

int rxqueue[1];
int txqueue[1];

struct sEthernetSocket {
    int rawSocket;
    bool isBind;
    struct sockaddr_ll socketAddress;
};

struct sEthernetHandleSet {
    struct pollfd *handles;
    int nhandles;
};

int init_dpdk(int argc, char *argv[]);

EthernetHandleSet
EthernetHandleSet_new(void)
{
    return 0;
}

void EthernetHandleSet_addSocket(EthernetHandleSet self, const EthernetSocket sock)
{
	printf("EthernetHandleSet_addSocket not implemented\n");
}

void EthernetHandleSet_removeSocket(EthernetHandleSet self, const EthernetSocket sock)
{
	printf("EthernetHandleSet_removeSocket not implemented\n");
}

int EthernetHandleSet_waitReady(EthernetHandleSet self, unsigned int timeoutMs)
{
	//printf("EthernetHandleSet_waitReady not implemented\n");
    return 1;
}

void EthernetHandleSet_destroy(EthernetHandleSet self)
{
	printf("EthernetHandleSet_destroy not implemented\n");
}

static int getInterfaceIndex(int sock, const char* deviceName)
{
	printf("getInterfaceIndex not implemented\n");
    return -1;
}


void Ethernet_getInterfaceMACAddress(const char* interfaceId, uint8_t* addr)
{
    addr[0] = rte_addr.addr_bytes[0];
    addr[1] = rte_addr.addr_bytes[1];
    addr[2] = rte_addr.addr_bytes[2];
    addr[3] = rte_addr.addr_bytes[3];
    addr[4] = rte_addr.addr_bytes[4];
    addr[5] = rte_addr.addr_bytes[5];
}


EthernetSocket
Ethernet_createSocket(const char* interfaceId, uint8_t* destAddress)
{
    EthernetSocket ethernetSocket = GLOBAL_CALLOC(1, sizeof(struct sEthernetSocket));

    char *argv[] = {"-c 4","-n 4","0"};// TODO pass this from application    
    int argc = sizeof(argv) / sizeof(char *); // TODO generate this from argument list
    printf("argc=%d\n",argc);
    
    int port = init_dpdk(argc, argv);
    ethernetSocket->rawSocket = port;
    return ethernetSocket;
}

void Ethernet_setProtocolFilter(EthernetSocket ethSocket, uint16_t etherType)
{
    ;//ethSocket->socketAddress.sll_protocol = htons(etherType);
    //static inline int app_link_filter_arp_add(struct app_link_params *link)
        struct rte_eth_ethertype_filter filter = {
                .ether_type = etherType,
                .flags = 0,
                .queue = rxqueue[0],
        };
        return rte_eth_dev_filter_ctrl(ethSocket->rawSocket,
                RTE_ETH_FILTER_ETHERTYPE,
                RTE_ETH_FILTER_ADD,
                &filter);


}


/* non-blocking receive */
int Ethernet_receivePacket(EthernetSocket self, uint8_t* buffer, int bufferSize)
{
	uint16_t port = self->rawSocket;
	/* Get burst of RX packets, from first port of pair. */
	struct rte_mbuf *bufs[1];
	const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
			bufs, 1);

	if (likely(nb_rx != 0))
	{
		uint8_t *pkt_data = rte_pktmbuf_mtod(bufs[0], uint8_t *);
		uint32_t pkt_len = rte_pktmbuf_pkt_len(bufs[0]) - sizeof(struct rte_ether_hdr);
		
		uint32_t len = pkt_len;
		if(pkt_len > (uint32_t)bufferSize)
			len = bufferSize;

		memcpy(buffer, pkt_data, len);
		/* Free any unsent packets. */
		rte_pktmbuf_free(bufs[0]);
		return len;
	}
	return 0;
}

void
Ethernet_sendPacket(EthernetSocket ethSocket, uint8_t* buffer, int packetSize)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mbuf_pool);
	if(m == NULL)
	{
		printf("cannot allocate rte_mbuf\n");
		return 0;
	}
    	rte_pktmbuf_reset(m);
	m->nb_segs = 1;
	m->next = NULL;
	//printf("len: %d\n", m->data_len);
	char *eth_hdr = rte_pktmbuf_append(m,m->data_len);
	if(eth_hdr == NULL)
	{
		printf("cannot allocate eth_hdr\n");
		return 0;
	}
	m->data_len = (uint16_t)packetSize;
	m->pkt_len =  (uint16_t)packetSize;
	//printf("allocated eth_hdr\n");
	rte_memcpy(eth_hdr, buffer, packetSize);
	//printf("memcpy done\n");

	uint16_t port = ethSocket->rawSocket;
    	//sendto(ethSocket->rawSocket, buffer, packetSize, 0, (struct sockaddr*) &(ethSocket->socketAddress), sizeof(ethSocket->socketAddress));
	int ret = rte_eth_tx_burst(port, 0, &m, 1);

	if(unlikely(ret < 1)) {
		rte_pktmbuf_free(m);
	}
}

void
Ethernet_destroySocket(EthernetSocket ethSocket)
{
	printf("Ethernet_destroySocket not implemented\n");
}

bool
Ethernet_isSupported()
{
    return true;
}





#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
        .txmode = {
                .offloads = DEV_TX_OFFLOAD_MULTI_SEGS,
        },
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		printf("init rx queue %d ok\n", q);
		if (retval < 0)
			return retval;
		else
			rxqueue[q] = retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		printf("init tx queue %d ok\n", q);
		if (retval < 0)
			return retval;
		else
			txqueue[q] = retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	
	retval = rte_eth_macaddr_get(port, &rte_addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			rte_addr.addr_bytes[0], rte_addr.addr_bytes[1],
			rte_addr.addr_bytes[2], rte_addr.addr_bytes[3],
			rte_addr.addr_bytes[4], rte_addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}


static int initialized = 0;
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int init_dpdk(int argc, char *argv[])
{
	
	unsigned nb_ports = 1;
	uint16_t portid = 0;

	if(initialized == 1)
	{
		printf("init already done\n");
		return 0;
	}

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	if(argc > 1 )
        {
		int num = -1;
		sscanf (argv[1],"%d",&num);
		if(num >= 0 && num < 0x10000)
		{
			portid = (uint16_t) num;
			printf("\nport %u set\n", portid);
		}
		else
			rte_exit(EXIT_FAILURE, "Error with port config, only numbers between 0 and 65535 allowed\n");
        }
	else
	{
		printf("\ndefault port %u set\n", portid);
	}

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE * 2, rte_eth_dev_socket_id(portid));

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	/* Call lcore_main on the master core only. */
	if (rte_eth_dev_socket_id(portid) > 0 && rte_eth_dev_socket_id(portid) != (int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to polling thread.\n\tPerformance will not be optimal.\n", portid);

	initialized = 1;

	return portid;
}
