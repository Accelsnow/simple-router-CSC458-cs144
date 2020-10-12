/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void handle_arp_packet(struct sr_instance *, unsigned int, uint8_t *, struct sr_arp_hdr *, struct sr_ethernet_hdr *);
void handle_ip_packet(struct sr_instance *, unsigned int, uint8_t *, struct sr_ip_hdr *, struct sr_ethernet_hdr *, char *);
struct sr_if *get_interface_by_ip(struct sr_instance *, uint32_t);
struct sr_if *get_interface_by_name(struct sr_instance *, char[sr_IFACE_NAMELEN]);
struct sr_rt *get_longest_prefix_match(struct sr_rt *, uint32_t);
void reply_arp(struct sr_instance *, unsigned int, uint8_t *, struct sr_ethernet_hdr *, struct sr_arp_hdr *, struct sr_if *);
void send_icmp_message(struct sr_instance *, unsigned int, uint8_t *, struct sr_ethernet_hdr *, struct sr_if *, struct sr_if *, struct sr_ip_hdr *, struct sr_icmp_hdr *, uint8_t, uint8_t);
void send_icmp_error(struct sr_instance *, unsigned int, uint8_t *, struct sr_ethernet_hdr *, struct sr_if *, struct sr_if *, struct sr_ip_hdr *, uint8_t, uint8_t);
void set_return_eth_ip_hdr(uint8_t *, struct sr_ethernet_hdr *, struct sr_if *, struct sr_if *, struct sr_ip_hdr *);
struct sr_ethernet_hdr *validate_ethernet_packet(uint8_t *, unsigned int);
struct sr_arp_hdr *validate_arp_packet(uint8_t *, unsigned int);
struct sr_ip_hdr *validate_ip_packet(uint8_t *, unsigned int);
struct sr_icmp_hdr *validate_icmp_packet(uint8_t *, unsigned int);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  struct sr_ethernet_hdr *eth_hdr = validate_ethernet_packet(packet, len);
  if (eth_hdr != NULL)
  {
    uint16_t eth_type = ethertype((uint8_t *)eth_hdr);

    switch (eth_type)
    {
    case ethertype_arp:;
      struct sr_arp_hdr *arp_hdr = validate_arp_packet(packet, len);
      if (arp_hdr != NULL)
      {
        handle_arp_packet(sr, len, packet, arp_hdr, eth_hdr);
      }
      break;

    case ethertype_ip:;
      struct sr_ip_hdr* ip_hdr = validate_ip_packet(packet, len);
      if (ip_hdr != NULL)
      {
        handle_ip_packet(sr, len, packet, ip_hdr, eth_hdr, interface);
      }
      break;
    }
  }

} /* end sr_ForwardPacket */

struct sr_ethernet_hdr *validate_ethernet_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr))
  {
    printf("!!! INVALID ETHERNET PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return NULL;
  }
  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
  return eth_hdr;
}

struct sr_arp_hdr *validate_arp_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
  {
    printf("!!! INVALID ARP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return NULL;
  }
  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  return arp_hdr;
}

struct sr_ip_hdr *validate_ip_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))
  {
    printf("!!! INVALID IP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return NULL;
  }
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  uint16_t prev_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t new_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
  ip_hdr->ip_sum = prev_sum;
  if (prev_sum != new_sum)
  {
    printf("!!! INVALID IP CHECKSUM! PACKET DROPPED!\n");
    return NULL;
  }

  return ip_hdr;
}

struct sr_icmp_hdr *validate_icmp_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr))
  {
    printf("!!! INVALID ICMP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return NULL;
  }
  struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  uint16_t prev_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t new_sum = cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
  icmp_hdr->icmp_sum = prev_sum;
  if (prev_sum != new_sum)
  {
    printf("!!! INVALID ICMP CHECKSUM! PACKET DROPPED!\n");
    return NULL;
  }

  return icmp_hdr;
}

void handle_ip_packet(struct sr_instance *sr, unsigned int len, uint8_t *packet /* lent */, struct sr_ip_hdr *ip_hdr,
                      struct sr_ethernet_hdr *eth_hdr, char *src_interface)
{
  printf("*** RECEIVED IP PACKET\n");
  print_hdrs(packet, len);
  uint8_t protocol = ip_protocol((uint8_t *)ip_hdr);
  uint32_t ip_dst = ip_hdr->ip_dst;

  struct sr_if *target_interface = get_interface_by_ip(sr, ip_dst);
  struct sr_if *source_interface = get_interface_by_name(sr, src_interface);
  struct sr_rt *longest_prefix_entry = get_longest_prefix_match(sr->routing_table, ip_dst);

  if (target_interface == NULL && longest_prefix_entry == NULL)
  {
    printf("*** DEST NET UNREACHABLE (NO ENTRY IN ROUTING TABLE AND NOT MY INTERFACE)\n");
    send_icmp_error(sr, len, packet, eth_hdr, target_interface, source_interface, ip_hdr, 3, 0);
    return;
  }

  if (target_interface != NULL)
  {
    printf("*** PACKET IS FOR MY INTERFACE\n");
    sr_print_if(target_interface);

    if (protocol == ip_protocol_icmp)
    {
      printf("*** IT IS AN IP ICMP PACKET\n");
      struct sr_icmp_hdr * icmp_hdr = validate_icmp_packet(packet, len);
      if (icmp_hdr != NULL)
      {
        if (icmp_hdr->icmp_type == 8)
        {
          printf("*** IT IS AN ICMP ECHO REQUEST. REPLY ICMP ECHO BACK.\n");
          send_icmp_message(sr, len, packet, eth_hdr, target_interface, source_interface, ip_hdr, icmp_hdr, 0, 0);
        }
        /* handle non-echo incoming icmp packet? */
      }
    }
    else
    {
      printf("*** IT IS A NON-ICMP IP PACKET\n");
      printf("*** REPLY ICMP PORT UNREACHABLE ERROR\n");
      send_icmp_error(sr, len, packet, eth_hdr, target_interface, source_interface, ip_hdr, 3, 3);
    }
  }
  else
  {
    /* TODO FORWARD PACKET */
  }
}

void send_icmp_message(struct sr_instance *sr, unsigned int len, uint8_t *packet, struct sr_ethernet_hdr *org_eth_hdr, struct sr_if *target_interface,
                       struct sr_if *source_interface, struct sr_ip_hdr *org_ip_hdr, struct sr_icmp_hdr *org_icmp_hdr, uint8_t icmp_type, uint8_t icmp_code)
{
  set_return_eth_ip_hdr(packet, org_eth_hdr, target_interface, source_interface, org_ip_hdr);

  struct sr_icmp_hdr *reply_icmp = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  reply_icmp->icmp_type = icmp_type;
  reply_icmp->icmp_code = icmp_code;
  reply_icmp->icmp_sum = 0;
  reply_icmp->icmp_sum = cksum(reply_icmp, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, source_interface->name);
  printf("*** END OF ICMP REPLY\n");
}

void send_icmp_error(struct sr_instance *sr, unsigned int len, uint8_t *packet, struct sr_ethernet_hdr *org_eth_hdr,
                     struct sr_if *target_interface, struct sr_if *source_interface, struct sr_ip_hdr *ip_hdr, uint8_t icmp_type, uint8_t icmp_code)
{
  set_return_eth_ip_hdr(packet, org_eth_hdr, target_interface, source_interface, ip_hdr);

  struct sr_icmp_t3_hdr *reply_icmp = (struct sr_icmp_t3_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  reply_icmp->icmp_type = icmp_type;
  reply_icmp->icmp_code = icmp_code;
  reply_icmp->unused = 0;
  reply_icmp->next_mtu = 0; /* may need this when code==4 */
  memcpy(reply_icmp->data, (uint8_t *)ip_hdr, ICMP_DATA_SIZE);
  reply_icmp->icmp_sum = cksum(reply_icmp, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, source_interface->name);
  printf("*** END OF ICMP ERROR REPLY\n");
}

void set_return_eth_ip_hdr(uint8_t *packet, struct sr_ethernet_hdr *org_eth_hdr, struct sr_if *target_interface,
                           struct sr_if *source_interface, struct sr_ip_hdr *org_ip_hdr)
{
  struct sr_ethernet_hdr *reply_eth = (struct sr_ethernet_hdr *)packet;
  reply_eth->ether_type = htons(ethertype_ip);
  memcpy(reply_eth->ether_dhost, org_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(reply_eth->ether_shost, source_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

  struct sr_ip_hdr *reply_ip = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  memcpy(reply_ip, org_ip_hdr, sizeof(struct sr_ip_hdr));
  reply_ip->ip_p = ip_protocol_icmp;
  reply_ip->ip_dst = org_ip_hdr->ip_src;
  reply_ip->ip_src = target_interface->ip;
  reply_ip->ip_sum = 0;
  reply_ip->ip_sum = cksum(reply_ip, sizeof(struct sr_ip_hdr));
}

void handle_arp_packet(struct sr_instance *sr, unsigned int len, uint8_t *packet /* lent */, struct sr_arp_hdr *arp_hdr, struct sr_ethernet_hdr *eth_hdr)
{
  printf("*** RECEIVED ARP REQUEST PACKET\n");
  print_hdr_eth((uint8_t *)eth_hdr);
  print_hdr_arp((uint8_t *)arp_hdr);
  unsigned short op = htons(arp_hdr->ar_op);
  uint32_t target_ip = arp_hdr->ar_tip;
  struct sr_if *target_interface = get_interface_by_ip(sr, target_ip);

  if (target_interface != NULL)
  {
    printf("*** INTERFACE FOUND\n");
    sr_print_if(target_interface);
    switch (op)
    {
    case arp_op_request:;
      printf("*** REPLY ARP REQUEST START\n");
      reply_arp(sr, len, packet, eth_hdr, arp_hdr, target_interface);
      break;

    case arp_op_reply:;
      printf("reply\n");
      break;
    }
  }
}

void reply_arp(struct sr_instance *sr, unsigned int len, uint8_t *packet, struct sr_ethernet_hdr *org_eth_hdr,
               struct sr_arp_hdr *arp_hdr, struct sr_if *target_interface)
{
  struct sr_ethernet_hdr *reply_eth = (struct sr_ethernet_hdr *)packet;
  reply_eth->ether_type = htons(ethertype_arp);
  memcpy(reply_eth->ether_dhost, org_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(reply_eth->ether_shost, target_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

  struct sr_arp_hdr *reply_arp = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  reply_arp->ar_op = htons(arp_op_reply);
  memcpy(reply_arp->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
  reply_arp->ar_tip = arp_hdr->ar_sip;
  memcpy(reply_arp->ar_sha, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
  reply_arp->ar_sip = target_interface->ip;

  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, target_interface->name);
  printf("*** END OF ARP REPLY\n");
}

struct sr_if *get_interface_by_ip(struct sr_instance *sr, uint32_t ip)
{
  struct sr_if *interface = sr->if_list;
  while (interface != NULL)
  {
    if (interface->ip == ip)
    {
      break;
    }
    interface = interface->next;
  }
  return interface;
}

struct sr_if *get_interface_by_name(struct sr_instance *sr, char name[sr_IFACE_NAMELEN])
{
  struct sr_if *interface = sr->if_list;
  while (interface != NULL)
  {
    if (strncmp(interface->name, name, sr_IFACE_NAMELEN) == 0)
    {
      break;
    }
    interface = interface->next;
  }
  return interface;
}

struct sr_rt *get_longest_prefix_match(struct sr_rt *rt, uint32_t ip)
{
  struct sr_rt *curr_entry = rt;
  struct sr_rt *result = NULL;
  uint32_t max_match = 0;

  while (curr_entry != NULL)
  {
    if ((curr_entry->mask.s_addr & ip) == curr_entry->dest.s_addr)
    {
      if (curr_entry->mask.s_addr > max_match)
      {
        max_match = curr_entry->mask.s_addr;
        result = curr_entry;
      }
    }
    curr_entry = curr_entry->next;
  }
  if (result != NULL)
  {
    printf("*** LPM: \n");
    print_addr_ip_int(ntohl(result->dest.s_addr));
    print_addr_ip_int(ntohl(result->gw.s_addr));
  }
  else
  {
    printf("*** LPM NOT FOUND\n");
  }
  return result;
}
