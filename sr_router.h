/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                        \
  do                                       \
  {                                        \
    int ivyl;                              \
    for (ivyl = 0; ivyl < 5; ivyl++)       \
      printf("%02x:",                      \
             (unsigned char)(x[ivyl]));    \
    printf("%02x", (unsigned char)(x[5])); \
  } while (0)
#else
#define Debug(x, args...) \
  do                      \
  {                       \
  } while (0)
#define DebugMAC(x) \
  do                \
  {                 \
  } while (0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0
#define ICMP_DEST_NET_UNREACHABLE_TYPE 3
#define ICMP_DEST_NET_UNREACHABLE_CODE 0
#define ICMP_DEST_HOST_UNREACHABLE_TYPE 3
#define ICMP_DEST_HOST_UNREACHABLE_CODE 1
#define ICMP_PORT_UNREACHABLE_TYPE 3
#define ICMP_PORT_UNREACHABLE_CODE 3
#define ICMP_TIME_EXCEEDED_TYPE 11
#define ICMP_TIME_EXCEEDED_CODE 0
#define ARP_IP_PROTOCOL 0x800
#define DEFAULT_TTL 64
#define DEFAULT_IP_VERSION 4
#define DEFAULT_IP_HDR_LEN 5
#define MAX_ARP_RETRY 5
#define RESEND_ARP_INTERVAL 1.0
#define ARP_BROADCAST_MAC_UNIT 0xff
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
  int sockfd;        /* socket to server */
  char user[32];     /* user name */
  char host[32];     /* host name */
  char template[30]; /* template name if any */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;  /* address to server */
  struct sr_if *if_list;       /* list of interfaces */
  struct sr_rt *routing_table; /* routing table */
  struct sr_arpcache cache;    /* ARP cache */
  pthread_attr_t attr;
  FILE *logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

/* added function headers */
int valid_icmp_packet(uint8_t *, unsigned int);
int valid_ip_packet(uint8_t *, unsigned int);
int valid_arp_packet(uint8_t *, unsigned int);
int valid_ethernet_packet(uint8_t *, unsigned int);
struct sr_rt *get_longest_prefix_match(struct sr_rt *, uint32_t);
struct sr_if *get_interface_by_name(struct sr_instance *, char[sr_IFACE_NAMELEN]);
struct sr_if *get_interface_by_ip(struct sr_instance *, uint32_t);
void handle_arp_packet(struct sr_instance *, unsigned int, uint8_t *, char *);
void send_arp_request(struct sr_instance *, struct sr_arpreq *);
void send_icmp_message(struct sr_instance *, uint8_t *, size_t, struct sr_if *, uint8_t, uint8_t);
void packet_switching(struct sr_instance *, unsigned int, uint8_t *, struct sr_if *, struct sr_rt *, int);
void handle_ip_packet(struct sr_instance *, unsigned int, uint8_t *, char *, int);
struct sr_ip_hdr *parse_ip_hdr(uint8_t *);
struct sr_ethernet_hdr *parse_eth_hdr(uint8_t *);
struct sr_arp_hdr *parse_arp_hdr(uint8_t *);
struct sr_icmp_hdr *parse_icmp_hdr(uint8_t *);
struct sr_icmp_t3_hdr *parse_icmp_t3_hdr(uint8_t *);

#endif /* SR_ROUTER_H */
