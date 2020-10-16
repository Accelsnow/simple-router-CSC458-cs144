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
  if (valid_ethernet_packet(packet, len))
  {
    struct sr_ethernet_hdr *eth_hdr = parse_eth_hdr(packet);
    uint16_t eth_type = ethertype((uint8_t *)eth_hdr);

    switch (eth_type)
    {
    case ethertype_arp:;
      if (valid_arp_packet(packet, len))
      {
        handle_arp_packet(sr, len, packet, interface);
      }
      break;

    case ethertype_ip:;
      if (valid_ip_packet(packet, len))
      {
        handle_ip_packet(sr, len, packet, interface, 0);
      }
      break;
    }
  }

} /* end sr_ForwardPacket */

void handle_ip_packet(struct sr_instance *sr, unsigned int len, uint8_t *packet /* lent */, char *src_interface, int was_waiting_arp)
{
  struct sr_ip_hdr *ip_hdr = parse_ip_hdr(packet);
  printf("*** RECEIVED IP PACKET\n");
  print_hdrs(packet, len);
  uint8_t protocol = ip_protocol((uint8_t *)ip_hdr);
  uint32_t ip_dst = ip_hdr->ip_dst;
  struct sr_if *target_interface = get_interface_by_ip(sr, ip_dst);
  struct sr_if *source_interface = get_interface_by_name(sr, src_interface);
  struct sr_rt *longest_prefix_entry = get_longest_prefix_match(sr->routing_table, ip_dst);

  if (target_interface != NULL)
  {
    printf("*** PACKET IS FOR MY INTERFACE\n");
    sr_print_if(target_interface);

    if (protocol == ip_protocol_icmp)
    {
      printf("*** IT IS AN IP ICMP PACKET\n");
      if (valid_icmp_packet(packet, len))
      {
        struct sr_icmp_hdr *icmp_hdr = parse_icmp_hdr(packet);
        if (icmp_hdr->icmp_type == ICMP_ECHO_REQUEST_TYPE)
        {
          printf("*** IT IS AN ICMP ECHO REQUEST. REPLY ICMP ECHO BACK.\n");
          send_icmp_message(sr, packet, len, source_interface, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REPLY_CODE);
        }
        /* handle non-echo incoming icmp packet? */
      }
    }
    else if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP)
    {
      printf("*** IT IS A TCP/UDP PACKET\n");
      printf("*** REPLY ICMP PORT UNREACHABLE ERROR\n");
      send_icmp_message(sr, packet, len, source_interface, ICMP_PORT_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE);
    }
  }
  else if (longest_prefix_entry != NULL)
  {
    packet_switching(sr, len, packet, source_interface, longest_prefix_entry, was_waiting_arp);
  }
  else
  {
    printf("*** DEST NET UNREACHABLE (NO ENTRY IN ROUTING TABLE AND NOT MY INTERFACE)\n");
    send_icmp_message(sr, packet, len, source_interface, ICMP_DEST_NET_UNREACHABLE_TYPE, ICMP_DEST_NET_UNREACHABLE_CODE);
  }
}

void packet_switching(struct sr_instance *sr, unsigned int len, uint8_t *packet /* lent */, struct sr_if *source_interface,
                      struct sr_rt *longest_prefix, int was_waiting_arp)
{
  struct sr_ethernet_hdr *eth_hdr = parse_eth_hdr(packet);
  struct sr_ip_hdr *ip_hdr = parse_ip_hdr(packet);

  if (!was_waiting_arp)
  {
    ip_hdr->ip_ttl--;
  }

  if (ip_hdr->ip_ttl > 0)
  {
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

    struct sr_if *target_interface = get_interface_by_name(sr, longest_prefix->interface);
    struct sr_arpentry *cached_arp = sr_arpcache_lookup((&sr->cache), longest_prefix->gw.s_addr);

    if (cached_arp != NULL)
    {
      printf("*** FOUND ARP CACHE. FORWARD PACKET.\n");
      memcpy(eth_hdr->ether_shost, target_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, cached_arp->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);

      print_hdrs(packet, len);
      sr_send_packet(sr, packet, len, target_interface->name);
      free(cached_arp);
    }
    else
    {
      printf("*** ARP CACHE NOT FOUND. SENDING ARP REQUEST.\n");
      memcpy(eth_hdr->ether_shost, target_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, longest_prefix->gw.s_addr, packet, len, longest_prefix->interface);
      send_arp_request(sr, arp_request);
    }
  }
  else
  {
    printf("!!! IP PACKET EXCEEDED MAX TTL!\n");
    printf("!!! SENDING ICMP TLE PACKET BACK TO SENDER.\n");
    send_icmp_message(sr, packet, len, source_interface, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
  }
}

void send_icmp_message(struct sr_instance *sr, uint8_t *org_packet, size_t org_len,
                       struct sr_if *source_interface, uint8_t icmp_type, uint8_t icmp_code)
{
  struct sr_ethernet_hdr *org_eth_hdr = parse_eth_hdr(org_packet);
  struct sr_ip_hdr *org_ip_hdr = (struct sr_ip_hdr *)(org_packet + sizeof(struct sr_ethernet_hdr));
  uint8_t *packet = malloc(org_len);
  memcpy(packet, org_packet, org_len);

  struct sr_ethernet_hdr *eth_hdr = parse_eth_hdr(packet);
  eth_hdr->ether_type = htons(ethertype_ip);
  memcpy(eth_hdr->ether_shost, source_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, org_eth_hdr->ether_shost, sizeof(unsigned char) * ETHER_ADDR_LEN);

  struct sr_ip_hdr *ip_hdr = parse_ip_hdr(packet);
  ip_hdr->ip_hl = DEFAULT_IP_HDR_LEN;
  ip_hdr->ip_v = DEFAULT_IP_VERSION;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = org_ip_hdr->ip_id;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = DEFAULT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_len = org_ip_hdr->ip_len;
  ip_hdr->ip_dst = org_ip_hdr->ip_src;

  if (icmp_type == 0)
  {
    ip_hdr->ip_src = org_ip_hdr->ip_dst;
    struct sr_icmp_hdr *reply_icmp = parse_icmp_hdr(packet);
    reply_icmp->icmp_type = icmp_type;
    reply_icmp->icmp_code = icmp_code;
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, org_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
  }
  else
  {
    if (icmp_type == ICMP_PORT_UNREACHABLE_TYPE)
    {
      ip_hdr->ip_src = org_ip_hdr->ip_dst;
    }
    else
    {
      ip_hdr->ip_src = source_interface->ip;
    }
    struct sr_icmp_t3_hdr *reply_icmp = parse_icmp_t3_hdr(packet);
    reply_icmp->icmp_type = icmp_type;
    reply_icmp->icmp_code = icmp_code;
    reply_icmp->unused = 0;
    reply_icmp->next_mtu = 0;
    memcpy(reply_icmp->data, org_ip_hdr, ICMP_DATA_SIZE);
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, org_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
  }

  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

  print_hdrs(packet, org_len);
  sr_send_packet(sr, packet, org_len, source_interface->name);
  free(packet);
  printf("*** END OF ICMP REPLY\n");
}

void send_arp_request(struct sr_instance *sr, struct sr_arpreq *request)
{
  if (difftime(time(NULL), request->sent) > RESEND_ARP_INTERVAL)
  {
    if (request->times_sent < MAX_ARP_RETRY)
    {
      struct sr_if *target_interface = get_interface_by_name(sr, request->packets->iface);
      size_t packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
      uint8_t *packet = malloc(packet_len);

      struct sr_ethernet_hdr *eth_hdr = parse_eth_hdr(packet);
      eth_hdr->ether_type = htons(ethertype_arp);
      memset(eth_hdr->ether_dhost, ARP_BROADCAST_MAC_UNIT, sizeof(unsigned char) * ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);

      struct sr_arp_hdr *arp_hdr = parse_arp_hdr(packet);
      arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
      arp_hdr->ar_pro = htons(ARP_IP_PROTOCOL);
      arp_hdr->ar_hln = ETHER_ADDR_LEN;
      arp_hdr->ar_pln = sizeof(uint32_t);
      arp_hdr->ar_op = htons(arp_op_request);
      memcpy(arp_hdr->ar_sha, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
      arp_hdr->ar_sip = target_interface->ip;
      memset(arp_hdr->ar_tha, ARP_BROADCAST_MAC_UNIT, sizeof(unsigned char) * ETHER_ADDR_LEN);
      arp_hdr->ar_tip = request->ip;

      sr_send_packet(sr, packet, packet_len, target_interface->name);
      free(packet);

      request->sent = time(NULL);
      request->times_sent++;
    }
    else
    {
      while (request != NULL)
      {
        send_icmp_message(sr, request->packets->buf, request->packets->len, get_interface_by_name(sr, request->packets->iface), ICMP_DEST_HOST_UNREACHABLE_TYPE, ICMP_DEST_HOST_UNREACHABLE_CODE);
        request = request->next;
      }
      sr_arpreq_destroy(&sr->cache, request);
    }
  }
}

void handle_arp_packet(struct sr_instance *sr, unsigned int org_len, uint8_t *org_packet /* lent */, char *interface)
{
  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(org_packet + sizeof(struct sr_ethernet_hdr));
  printf("*** RECEIVED ARP PACKET\n");
  print_hdrs(org_packet, org_len);
  unsigned short arp_op = htons(arp_hdr->ar_op);
  struct sr_if *target_interface = get_interface_by_name(sr, interface);
  struct sr_arpentry *cached_arp = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);

  if (cached_arp == NULL)
  {
    printf("*** THIS ARP NOT CACHED. CACHING.\n");
    struct sr_arpreq *arp_request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (arp_request != NULL)
    {
      printf("*** CACHED ARP HAS QUEUED PACKETS. SENDING THEM\n");
      struct sr_packet *curr_packet = arp_request->packets;

      while (curr_packet != NULL)
      {
        struct sr_ethernet_hdr *eth_hdr = parse_eth_hdr(curr_packet->buf);

        if (ethertype((uint8_t *)eth_hdr) == ethertype_arp)
        {
          printf("??? MAYBE A BUG. SHOULD NOT HAVE ARP WAITING FOR ARP.\n");
          handle_arp_packet(sr, curr_packet->len, curr_packet->buf, interface);
        }
        else if (ethertype((uint8_t *)eth_hdr) == ethertype_ip)
        {
          printf("*** PROCESSING QUEUED IP PACKET.\n");
          handle_ip_packet(sr, curr_packet->len, curr_packet->buf, interface, 1);
        }

        free(curr_packet->buf);
        curr_packet = curr_packet->next;
      }
    }
  }
  else
  {
    free(cached_arp);
  }

  if (arp_op == arp_op_request)
  {
    printf("*** SENDING ARP REPLY\n");
    size_t packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
    uint8_t *packet = malloc(packet_len);

    struct sr_ethernet_hdr *re_eth_hdr = parse_eth_hdr(packet);
    re_eth_hdr->ether_type = htons(ethertype_arp);
    memcpy(re_eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    memcpy(re_eth_hdr->ether_shost, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);

    struct sr_arp_hdr *re_arp_hdr = parse_arp_hdr(packet);
    re_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    re_arp_hdr->ar_pro = htons(ARP_IP_PROTOCOL);
    re_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    re_arp_hdr->ar_pln = sizeof(uint32_t);
    re_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(re_arp_hdr->ar_sha, target_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
    re_arp_hdr->ar_sip = target_interface->ip;
    memcpy(re_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
    re_arp_hdr->ar_tip = arp_hdr->ar_sip;

    print_hdrs(packet, packet_len);

    sr_send_packet(sr, packet, packet_len, target_interface->name);
    free(packet);
  }
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
    printf("*** LPM (gw / dest): \n");
    print_addr_ip_int(ntohl(result->gw.s_addr));
    print_addr_ip_int(ntohl(result->dest.s_addr));
  }
  else
  {
    printf("*** LPM NOT FOUND\n");
  }
  return result;
}

int valid_ethernet_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr))
  {
    printf("!!! INVALID ETHERNET PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return 0;
  }
  return 1;
}

int valid_arp_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
  {
    printf("!!! INVALID ARP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return 0;
  }
  return 1;
}

int valid_ip_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))
  {
    printf("!!! INVALID IP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return 0;
  }
  struct sr_ip_hdr *ip_hdr = parse_ip_hdr(packet);
  uint16_t prev_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t new_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
  ip_hdr->ip_sum = prev_sum;
  if (prev_sum != new_sum)
  {
    printf("!!! INVALID IP CHECKSUM! PACKET DROPPED!\n");
    return 0;
  }

  return 1;
}

int valid_icmp_packet(uint8_t *packet, unsigned int len)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr))
  {
    printf("!!! INVALID ICMP PACKET LENGTH OR INCOMPLETE PACKET! PACKET DROPPED!\n");
    return 0;
  }
  struct sr_icmp_hdr *icmp_hdr = parse_icmp_hdr(packet);
  uint16_t prev_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  uint16_t new_sum = cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
  icmp_hdr->icmp_sum = prev_sum;
  if (prev_sum != new_sum)
  {
    printf("!!! INVALID ICMP CHECKSUM! PACKET DROPPED!\n");
    return 0;
  }

  return 1;
}

struct sr_ip_hdr *parse_ip_hdr(uint8_t *packet)
{
  return (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

struct sr_ethernet_hdr *parse_eth_hdr(uint8_t *packet)
{
  return (struct sr_ethernet_hdr *)packet;
}

struct sr_arp_hdr *parse_arp_hdr(uint8_t *packet)
{
  return (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

struct sr_icmp_hdr *parse_icmp_hdr(uint8_t *packet)
{
  return (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
}

struct sr_icmp_t3_hdr *parse_icmp_t3_hdr(uint8_t *packet)
{
  return (struct sr_icmp_t3_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
}