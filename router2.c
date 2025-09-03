#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

void print_mac(uint8_t mac[6]);

typedef struct {
	struct ether_hdr *ether_hdr;
	struct ip_hdr *ip_hdr;
	struct arp_hdr *arp_hdr;
	int type; // type 1 will be ip_hdr, type 2 will be arp_hdr
} packet_s;

typedef struct {
	uint32_t ip;
	uint8_t mac[6];
} ip_mac_s;

typedef struct {
	packet_s *packet;
	size_t len;
	size_t interface;
	uint32_t next_ip;
} packet_len_interface_nextIP_s;

void print_packet_struct(packet_s packet) {
	if(packet.ether_hdr != NULL) {
		printf("Destination MAC: ");
		print_mac(packet.ether_hdr->ethr_dhost);
		printf("Source MAC: ");
		print_mac(packet.ether_hdr->ethr_shost);
		printf("Eth type (Hex): %04X\n", ntohs(packet.ether_hdr->ethr_type));
	} else {
		printf("Eth Header NULL\n");
	}
	if (packet.arp_hdr != NULL) {
		printf("Format of hardware address: %hu\n", ntohs(packet.arp_hdr->hw_type));
		printf("Format of protocol address: %hu\n", ntohs(packet.arp_hdr->proto_type));
		printf("Length of hardware address: %hhu\n", packet.arp_hdr->hw_len);
		printf("Length of protocol address: %hhu\n", packet.arp_hdr->proto_len);
		printf("ARP opcode (command): %hu\n", ntohs(packet.arp_hdr->opcode));
	
		printf("Sender hardware address: ");
		print_mac(packet.arp_hdr->shwa);
	
		struct in_addr addr;
		addr.s_addr = packet.arp_hdr->sprotoa;
		printf("Sender IP address: %s\n", inet_ntoa(addr));
	
		printf("Target hardware address: ");
		print_mac(packet.arp_hdr->thwa);
	
		addr.s_addr = packet.arp_hdr->tprotoa;
		printf("Target IP address: %s\n", inet_ntoa(addr));
	} else {
		printf("Arp Hdr NULL\n");
	}
	if(packet.ip_hdr != NULL) {
		printf("Version: %u\n", packet.ip_hdr->ver);
		printf("Header Length (IHL): %u (in 32-bit words)\n", packet.ip_hdr->ihl);
		printf("Type of Service (TOS): %u\n", packet.ip_hdr->tos);
		printf("Total Length: %u\n", ntohs(packet.ip_hdr->tot_len));
		printf("ID: %u\n", ntohs(packet.ip_hdr->id));
		printf("Fragment offset & flags: %u\n", ntohs(packet.ip_hdr->frag));
		printf("Time to Live (TTL): %u\n", packet.ip_hdr->ttl);
		printf("Protocol: %u\n", packet.ip_hdr->proto);
		printf("Checksum: 0x%04X\n", ntohs(packet.ip_hdr->checksum));
	
		struct in_addr addr;
		addr.s_addr = packet.ip_hdr->source_addr;
		printf("Source IP address: %s\n", inet_ntoa(addr));
	
		addr.s_addr = packet.ip_hdr->dest_addr;
		printf("Destination IP address: %s\n", inet_ntoa(addr));
	} else {
		printf("IP Hdr NULL\n");
	}
}

void print_mac(uint8_t mac[6]) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int same_mac(uint8_t mac1[6], uint8_t mac2[6]) {
	for (int i = 0; i < 6; i++) {
		if (mac1[i] != mac2[i])
			return 0;
	}
	return 1;
}

int same_ip(uint32_t ip1, uint32_t ip2) {
    return ip1 == ip2;
}

uint8_t *get_mac_from_array_ip(ip_mac_s *v, int size, uint32_t ip) {
	if (!v)
		return NULL;

	for (int i = 0; i < size; i++) {
		if (same_ip(v[i].ip, ip)) {
			return v[i].mac;
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	ip_mac_s cache[100];
	int size = 0;
	
	char *rtable_path = argv[1];
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rc = read_rtable(rtable_path, rtable);
	if(rc <= 0)
		return -1;

	queue q = create_queue();
		
	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		uint8_t zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t my_mac[6];
		uint32_t my_ip;
		my_ip = inet_addr(get_interface_ip(interface));
		get_interface_mac(interface, my_mac);
		
		packet_s packet;
		packet.ether_hdr = (struct ether_hdr *) buf;
		if (ntohs(packet.ether_hdr->ethr_type) == 0x0800)
			packet.type = 1;
		else if (ntohs(packet.ether_hdr->ethr_type) == 0x0806)
			packet.type = 2;
		else packet.type = -1;

		printf("\n");
		printf("My mac: ");
		print_mac(my_mac);
		struct in_addr addr;
		addr.s_addr = my_ip;
		printf("My IP: %s\n", inet_ntoa(addr));

		//print_packet_struct(packet);

		if (same_mac(packet.ether_hdr->ethr_dhost, my_mac) == 0 && same_mac(packet.ether_hdr->ethr_dhost, broadcast_mac) == 0) {
			printf("This packet does not concern us\n");
			continue;
		}

		switch(packet.type) {
			case 1: // ip_hdr
				if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) {
					printf("Error: The packet is too small (ip_hdr)\n");
					continue;
				}
				printf("We are in the ip_hdr case\n");

				packet.ip_hdr = (struct ip_hdr *)((char *)packet.ether_hdr + sizeof(struct ether_hdr));
				packet.arp_hdr = NULL;

				print_packet_struct(packet);

				// we check if we are the destination
				if(same_ip(my_ip, packet.ip_hdr->dest_addr)) { // dest_addr == my_ip
					printf("I am the destination of the IP packet\n");
					continue;
				}

				// we check checksum
				uint16_t packet_checksum = ntohs(packet.ip_hdr->checksum);
				packet.ip_hdr->checksum = 0; // we set the checksum to 0 before calculating it

				uint16_t my_checksum = checksum((uint16_t *)packet.ip_hdr, packet.ip_hdr->ihl * 4);
				if (packet_checksum != my_checksum) {
					printf("The packet lost information (modified) (checksum does not match) (packet checksum: %hu | my_checksum: %hu)\n", packet_checksum, my_checksum);
					continue;
				}

				// we decrement TTL
				if (packet.ip_hdr->ttl <= 1) { // if ttl is smaller or equal to 1 we send an ICMP "Time Exceeded"
					printf("TTL was %hhu\n", packet.ip_hdr->ttl);
					continue; // do stuff
				}
				packet.ip_hdr->ttl--;
				
				// search in rtable (Longest prefix match)
				uint32_t best_next_hop = 0;
				uint32_t biggest_mask = 0;
				size_t interface_to_go = -1;
				
				for (int i = 0; i < rc; i++) {
					if ((packet.ip_hdr->dest_addr & rtable[i].mask) == rtable[i].prefix) {
						if (rtable[i].mask > biggest_mask) {
							biggest_mask = rtable[i].mask;
							best_next_hop = rtable[i].next_hop;
							interface_to_go = rtable[i].interface;
						}
					}
				}
				
				if (interface_to_go == (size_t) -1) { // if we did not find anything
					continue; // do stuff
				}
				
				// modify checksum : from here we cannod modify the ip_hdr anymore
				packet.ip_hdr->checksum = checksum((uint16_t *)packet.ip_hdr, packet.ip_hdr->ihl * 4);
				
				// modify the addresses of the packet
				memcpy(packet.ether_hdr->ethr_shost, my_mac, 6);
				memcpy(packet.ether_hdr->ethr_dhost, zero_mac, 6);

				for(int i = 0; i < size; i++) {
					uint8_t *mac;
					mac = get_mac_from_array_ip(cache, size, best_next_hop);
					if(mac) {
						memcpy(packet.ether_hdr->ethr_dhost, mac, 6);
						//send_to_link(len, buf, interface_to_go);
						continue;
					}
				}
				
				// create packet clone
				packet_s *packet_clone = malloc(len);
				memcpy(packet_clone, buf, len);
				
				printf("\nCloned packet:\n");
				print_packet_struct(*packet_clone);
				
				packet_len_interface_nextIP_s *cell = malloc(sizeof(packet_len_interface_nextIP_s));
				cell->packet = packet_clone;
				cell->len = len;
				cell->interface = interface_to_go;
				cell->next_ip = best_next_hop;
				queue_enq(q, cell);
				
				// find the mac for next hop
					// verify if we already have the mac in cache (we will use a hash table)
					// if not, we find the correct interface with longest prefix match
					// we make an arp request packet
				char *arp_req_buf = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
					
				struct arp_hdr *arp_packet = (struct arp_hdr *)((char *)arp_req_buf + sizeof(struct ether_hdr));
				arp_packet->hw_type = htons(1);
				arp_packet->proto_type = htons(0x0800);
				arp_packet->hw_len = 6;
				arp_packet->proto_len = 4;
				arp_packet->opcode = htons(1);
				memcpy(arp_packet->shwa, my_mac, 6);
				arp_packet->sprotoa = my_ip;
				memcpy(arp_packet->thwa, zero_mac, 6);
				arp_packet->tprotoa = best_next_hop;

				struct ether_hdr *ether_packet = (struct ether_hdr *)(arp_req_buf);
				memcpy(ether_packet->ethr_dhost, broadcast_mac, 6);
				memcpy(ether_packet->ethr_shost, my_mac, 6);
				ether_packet->ethr_type = htons(0x0806);

					// we send to link the packet
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_req_buf, interface_to_go);
				printf("\n We have sent an ARP Request\n");
				//print_packet_struct()
				free(arp_req_buf);

				// sent the packet
				break;
			case 2: // arp_hdr
				if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr)) {
					printf("Error: The packet is too small (arp_hdr)\n");
					continue;
				}
				printf("We are in the arp_hdr case\n");
				packet.arp_hdr = (struct arp_hdr *)((char *)packet.ether_hdr + sizeof(struct ether_hdr));
				packet.ip_hdr = NULL;
				print_packet_struct(packet);

				if (ntohs(packet.arp_hdr->opcode) == 1) { // request
					printf("Am intrat pe ramura opcode == 1\n");
					if (packet.arp_hdr->tprotoa == my_ip) { // target == my_ip
						printf("Am intrat pe ramura target IP == my_ip\n");
						memcpy(packet.ether_hdr->ethr_dhost, packet.ether_hdr->ethr_shost, 6);
						memcpy(packet.ether_hdr->ethr_shost, my_mac, 6);

						packet.arp_hdr->tprotoa = packet.arp_hdr->sprotoa;
						packet.arp_hdr->sprotoa = my_ip;
						memcpy(packet.arp_hdr->thwa, packet.arp_hdr->shwa, 6);
						packet.arp_hdr->opcode = htons(2);
						memcpy(packet.arp_hdr->shwa, my_mac, 6);

						send_to_link(len, buf, interface);

						printf("\n");
						printf("We sent this packet:\n");
						print_packet_struct(packet);
					}
				} else if (ntohs(packet.arp_hdr->opcode) == 2) { // reply
					printf("We received an arp reply\n");
					if(get_mac_from_array_ip(cache, size, packet.arp_hdr->sprotoa)) { // daca este deja in cache
						printf("It is already in cache\n");
						continue;
					}
					printf("It is not in cache\n");

					cache[size].ip = packet.arp_hdr->sprotoa;
					memcpy(cache[size].mac, packet.arp_hdr->shwa, 6);
					size++;

					while(!queue_empty(q)) {
						packet_len_interface_nextIP_s *cell = queue_deq(q);
						packet_s *packet_to_send = cell->packet;
						if(same_ip(cell->next_ip, packet.arp_hdr->sprotoa)) {
							memcpy(packet_to_send->ether_hdr->ethr_dhost, packet.arp_hdr->shwa, 6);
							printf("\nPacket to send:\n");
							print_packet_struct(*packet_to_send);
							
							send_to_link(cell->len, (char *)packet_to_send, cell->interface);
						}
						free(cell);
					}
				}
				break;
			default:
				printf("Error on packet type\n");
				continue;
		}
	}
}


// TODO: Implement the router forwarding logic


/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
