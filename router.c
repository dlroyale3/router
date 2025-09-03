#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

#define ICMP_MTYPE_DESTINATION_UNREACHABLE 3
#define ICMP_MTYPE_TIME_EXCEEDED 11
#define ICMP_MTYPE_ECHO_REPLY 0
#define ICMP_MTYPE_ECHO_REQUEST 8
#define PACKET_TYPE_IP 1
#define PACKET_TYPE_ARP 2
#define IP_HDR 0x0800
#define ARP_HDR 0x0806
#define REQUEST_CODE 1
#define REPLY_CODE 2
#define RTABLE_SIZE 80000
#define MAX_CACHE_SIZE 1000
#define ETHER_HDR_SIZE sizeof(struct ether_hdr)
#define ARP_HDR_SIZE sizeof(struct arp_hdr)
#define IP_HDR_SIZE sizeof(struct ip_hdr)
#define ICMP_HDR_SIZE sizeof(struct icmp_hdr)
#define MAX_NR_OF_MASCS 32

typedef struct {
    struct ether_hdr *ether_hdr;
    struct ip_hdr *ip_hdr;
    struct arp_hdr *arp_hdr;
    int type; // type 1 o sa fie ip_hdr, type 2 o sa fie arp_hdr
} packet_s;

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
} cache_cell_s;

typedef struct {
    cache_cell_s cache[MAX_CACHE_SIZE];
    int nr_of_elem;
} cache_s;

typedef struct {
    packet_s *packet;
    size_t len;
    struct route_table_entry* rtable_cell;
} queue_cell_s;

void print_ip(uint32_t ip) {
    struct in_addr addr;
	addr.s_addr = ip; 
    printf("%s", inet_ntoa(addr));
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

uint8_t* get_mac_from_cache(cache_s *cache_full, uint32_t ip_to_find) {
    cache_cell_s *cache = cache_full->cache;
    for (int i = 0; i < cache_full->nr_of_elem; i++) {
        if (same_ip(cache[i].ip, ip_to_find))
            return cache[i].mac;
    }

    return NULL;
}

void send_arp_request(uint8_t *my_mac, uint32_t my_ip, uint8_t *zero_mac, uint32_t next_hop, uint8_t *broadcast_mac, size_t interface) {
    size_t len = ETHER_HDR_SIZE + ARP_HDR_SIZE;
    char *buf = malloc(len);

    struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)buf + ETHER_HDR_SIZE);

    arp_hdr->hw_type = htons(1);
    arp_hdr->proto_type = htons(IP_HDR);
    arp_hdr->hw_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(REQUEST_CODE);
    memcpy(arp_hdr->shwa, my_mac, 6);
    arp_hdr->sprotoa = my_ip;
    memcpy(arp_hdr->thwa, zero_mac, 6);
    arp_hdr->tprotoa = next_hop;

    struct ether_hdr *ether_hdr = (struct ether_hdr *)(buf);

    memcpy(ether_hdr->ethr_dhost, broadcast_mac, 6);
    memcpy(ether_hdr->ethr_shost, my_mac, 6);
    ether_hdr->ethr_type = htons(ARP_HDR);

    send_to_link(len, buf, interface);

    packet_s packet;
    printf("%p\n", &packet);

    packet.ether_hdr = ether_hdr;
    packet.arp_hdr = arp_hdr;
    packet.ip_hdr = NULL;
    packet.type = 2;

    free(buf);
}

int has_queue_same_next_hop(queue q, uint32_t next_hop) {
    queue_cell_s *queue_cell = NULL;
    queue temp_q = create_queue();

    int result = 0;
    
    while (!queue_empty(q)) {
        queue_cell = queue_deq(q);

        queue_enq(temp_q, queue_cell);
        
        if (same_ip(queue_cell->rtable_cell->next_hop, next_hop)) {
            result = 1;
        }
    }

    q = temp_q;

    return result;
}

int compare_ip(uint32_t ip1, uint32_t ip2) {
    // Functia compara adresele ip byte cu byte
    uint8_t byte1, byte2;

    byte1 = ip1 & 0xFF;
    byte2 = ip2 & 0xFF;
    if (byte1 < byte2) return -1;
    if (byte1 > byte2) return 1;

    byte1 = (ip1 >> 8) & 0xFF;
    byte2 = (ip2 >> 8) & 0xFF;
    if (byte1 < byte2) return -1;
    if (byte1 > byte2) return 1;

    byte1 = (ip1 >> 16) & 0xFF;
    byte2 = (ip2 >> 16) & 0xFF;
    if (byte1 < byte2) return -1;
    if (byte1 > byte2) return 1;

    byte1 = (ip1 >> 24) & 0xFF;
    byte2 = (ip2 >> 24) & 0xFF;
    if (byte1 < byte2) return -1;
    if (byte1 > byte2) return 1;

    return 0;
}

int compare(const void *x,const void *y) {
    struct route_table_entry *ob1 = (struct route_table_entry*)x;
    struct route_table_entry *ob2 = (struct route_table_entry*)y;

    if (ob1->mask > ob2->mask) return -1;
    if (ob1->mask < ob2->mask) return 1;
    if (ob1->mask == ob2->mask) {
        return compare_ip(ob1->prefix, ob2->prefix);
    }
    return 0;
}

struct route_table_entry *my_binary_search(struct route_table_entry *rtable, uint32_t result, int l, int r) {
    if (!rtable) {
        return NULL;
    }

    while (l <= r) {
        int mid = (l + r) / 2;

        if (compare_ip(result, rtable[mid].prefix) == 0) return rtable + mid;
        if (compare_ip(result, rtable[mid].prefix) == 1) {
            l = mid + 1;
        }
        if (compare_ip(result, rtable[mid].prefix) == -1) {
            r = mid - 1;
        }
    }

    return NULL;
}

int findFirst(struct route_table_entry *v, uint32_t x, int n) {
    int left = 0, right = n - 1, mid, res = -1;
    while (left <= right) {
        mid = (left + right) / 2;
        if (v[mid].mask <= x) {
            res = mid;
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return (res != -1 && v[res].mask == x) ? res : -1;
}

int findLast(struct route_table_entry *v, uint32_t x, int n) {
    int left = 0, right = n - 1, mid, res = -1;
    while (left <= right) {
        mid = (left + right) / 2;
        if (v[mid].mask >= x) {
            res = mid;
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return (res != -1 && v[res].mask == x) ? res : -1;
}

typedef struct {
    uint32_t mask;
    int l;
    int r;
} mask_l_r_s;

int main(int argc, char *argv[])
{
    printf("Am intrat in main\n");

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

    // Aici o sa adaug variabile de care o sa mai am nevoie la fiecare iteratie din while
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t zero_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Declar rtable si il sortez (descrescator dupa masca si in caz de egalitate, crescator dupa prefix)
    char *rtable_path = argv[1];
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * RTABLE_SIZE);
	int rc = read_rtable(rtable_path, rtable);
    qsort(rtable, rc, sizeof(struct route_table_entry), compare);
	if(rc <= 0)
		return -1;
    
    // O sa folosim un vector (v) care contine elemente de tipul
    // mask | l | r, unde l si r sunt primele / ultimele pozitii ale mastii in vectorul rtable
    // Cand o sa cautam cu Longest Prefix Match, o sa luam la rand (descrescator, deci de la masca cea mai mare) fiecare element al vectorului v
    // care are l si r diferite de -1 (adica care au acel prefix in tabel)
    mask_l_r_s v[MAX_NR_OF_MASCS];

    // Acest vector contine toate mastile posibile. Fiecare masca din acest vector va ajunge in v
    uint32_t masks[] = {
        0xFFFFFFFF,
        0xFEFFFFFF,
        0xFCFFFFFF,
        0xF8FFFFFF,
        0xF0FFFFFF,
        0xE0FFFFFF,
        0xC0FFFFFF,
        0x80FFFFFF,
        0x00FFFFFF,
        0x00FEFFFF,
        0x00FCFFFF,
        0x00F8FFFF,
        0x00F0FFFF,
        0x00E0FFFF,
        0x00C0FFFF,
        0x0080FFFF,
        0x0000FFFF,
        0x0000FEFF,
        0x0000FCFF,
        0x0000F8FF,
        0x0000F0FF,
        0x0000E0FF,
        0x0000C0FF,
        0x000080FF,
        0x000000FF,
        0x000000FE,
        0x000000FC,
        0x000000F8,
        0x000000F0,
        0x000000E0,
        0x000000C0,
        0x00000080,
        0x00000000
    };
    
    // Populam vectorul v in felul urmator: fiecare element are masca corespunzatoare si delimitarile
    // aparitiei ei in vectorul de entriuri original
    for (int i = 0; i < MAX_NR_OF_MASCS; i++) {
        v[i].mask = masks[i];
        v[i].l = findFirst(rtable, v[i].mask, rc);
        if (v[i].l != -1)
            v[i].r = findLast(rtable, v[i].mask, rc);
        else
            v[i].r = -1;
    }

    // Declar cache, care va tine structuri ip-mac
    // cache_full va contine atat cache cat si nr de elemente din el
    cache_s cache_full;
    cache_full.nr_of_elem = 0;
    
    // Declar queue, in care vom tine pachetele care inca nu au fost trimise pentru ca
    // asteapta un ARP REPLY (elementele cozii contin mai multe informatii despre pachet)
    queue q = create_queue();
    
    while (1) {

        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

        // Aici o sa adaug variabile de care o sa am nevoie la 1 iteratie
        uint32_t my_ip_recv;
        my_ip_recv = inet_addr(get_interface_ip(interface));
        uint32_t my_ip_send;

        uint8_t my_mac_recv[6];
        get_interface_mac(interface, my_mac_recv);
        // Adresa MAC destinatie o sa fie in functie de interfata pe care trimitem pachetul, deci trebuie modificata in cod cand trimitem
        uint8_t my_mac_send[6];
        
        packet_s *packet = malloc(sizeof(packet_s));

        // De aici o sa incepem sa parsam pachetul
		packet->ether_hdr = (struct ether_hdr *) buf;
        struct ether_hdr *ether_hdr = packet->ether_hdr;
        
		if (ntohs(packet->ether_hdr->ethr_type) == IP_HDR)
			packet->type = 1;
		else if (ntohs(packet->ether_hdr->ethr_type) == ARP_HDR)
			packet->type = 2;
		else packet->type = -1;

        if (packet->type == -1) {
            continue;
        }

        if (!same_mac(ether_hdr->ethr_dhost, my_mac_recv) && !same_mac(ether_hdr->ethr_dhost, broadcast_mac)) {
			continue;
		}

        switch (packet->type) {
            case PACKET_TYPE_IP:

                if (len < ETHER_HDR_SIZE + IP_HDR_SIZE)
                    continue;

                packet->ip_hdr = (struct ip_hdr *)((char *)ether_hdr + ETHER_HDR_SIZE);
				packet->arp_hdr = NULL;
                
                struct ip_hdr *ip_hdr = packet->ip_hdr;
                
                // Tot ce este aici este inca in Network order
                uint8_t ihl = ip_hdr->ihl;
                uint8_t ttl = ip_hdr->ttl;
                uint16_t packet_checksum = ip_hdr->checksum;
                uint32_t dest_addr = ip_hdr->dest_addr;

                // Verific daca eu sunt destinatia
                if (same_ip(dest_addr, my_ip_recv)) {

                    // Trebuie sa fac ICMP
                    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr + IP_HDR_SIZE);

                    // Verific daca am primit un ICMP de tip Echo_Request
                    if (icmp_hdr->mtype == ICMP_MTYPE_ECHO_REQUEST) {

                        // Trebuie sa modific type in Reply
                        icmp_hdr->mtype = ICMP_MTYPE_ECHO_REPLY;

                        // Trebuie sa modific check (din icmp_hdr)
                        icmp_hdr->check = 0;
                        icmp_hdr->check = checksum((uint16_t *)icmp_hdr, ICMP_HDR_SIZE);

                        // Trebuie sa modific adresele atat din ether_hdr, cat si din ip_hdr
                        memcpy(ether_hdr->ethr_dhost, ether_hdr->ethr_shost, 6);
                        memcpy(ether_hdr->ethr_shost, my_mac_recv, 6);

                        ip_hdr->ttl--;
                        ip_hdr->dest_addr = ip_hdr->source_addr;
                        ip_hdr->source_addr = my_ip_recv;
                        
                        // Modificam checksum. De aici nu mai putem sa modificam ip_hdr
                        ip_hdr->checksum = 0;
                        ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ihl * 4));

                        send_to_link(len, buf, interface);
                        
                    }
                    
                    continue;
                }

                // Setam checksum pe 0 inainte sa il recalculam
                ip_hdr->checksum = 0;

                // Acum calculam propriul checksum, care masoara pentru headerul IP
                uint16_t my_checksum = checksum((uint16_t *)ip_hdr, ihl * 4);
                
                if (ntohs(packet_checksum) != my_checksum) {
                    continue;
                }
                
                // Decrementam TTL daca este mai mare decat 1
                if (ttl <= 1) {
                    // Trebuie sa trimit ICMP Time exceeded
                    // Pentru a face acest lucru trebuie sa creez un pachet care sa contina:
                    // eth_hdr modificat | ip_hdr modificat | icmp_hdr | vechiul ip_hdr | primii 8 bytes de dupa ip_hdr din pachetul original

                    // Calculam noua dimensiune necesara
                    int total_hdr_size = ETHER_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE;
                    int payload_size = IP_HDR_SIZE + 8; // 8 extra bytes
                    int total_size = total_hdr_size + payload_size;

                    // Alocam spatiu suficient
                    char *new_buf = calloc(total_size, sizeof(char));

                    // Pentru usurinta, copiem ether_hdr si ip_hdr urmand sa le modificam
                    memcpy(new_buf, buf, ETHER_HDR_SIZE + IP_HDR_SIZE);

                    // Stabilim pointerii headerelor din noul pachet
                    struct ether_hdr *new_ether_hdr = (struct ether_hdr *) new_buf;
                    struct ip_hdr *new_ip_hdr = (struct ip_hdr *)((char *)new_ether_hdr + ETHER_HDR_SIZE);
                    struct icmp_hdr *new_icmp_hdr = (struct icmp_hdr *)((char *)new_ip_hdr + IP_HDR_SIZE);
                    struct ip_hdr *old_ip_hdr = (struct ip_hdr *)((char *)new_icmp_hdr + ICMP_HDR_SIZE);

                    // Modificam new_ether_hdr sa fie corect
                    memcpy(new_ether_hdr->ethr_dhost, ether_hdr->ethr_shost, 6);
                    memcpy(new_ether_hdr->ethr_shost, ether_hdr->ethr_dhost, 6);

                    // Modificam new_ip_hdr sa fie corect

                    // Noua lungime (lungimea header-ului ip + lungimea payloadului)
                    new_ip_hdr->tot_len = htons(IP_HDR_SIZE + payload_size);

                    // Resetam ttl la o noua valoare
                    new_ip_hdr->ttl = 20; 

                    // Punem protocolul pe 1, pentru ICMP
                    new_ip_hdr->proto = 1;

                    // Modificam adresele ip dest-sursa din header
                    new_ip_hdr->dest_addr = ip_hdr->source_addr;
                    new_ip_hdr->source_addr = my_ip_recv;

                    // Modificam checksum
                    new_ip_hdr->checksum = 0;
                    new_ip_hdr->checksum = htons(checksum((uint16_t *)new_ip_hdr, new_ip_hdr->ihl * 4));
                    
                    // Trebuie sa completam campurile din new_icmp_hdr;
                    new_icmp_hdr->mtype = ICMP_MTYPE_TIME_EXCEEDED;
                    new_icmp_hdr->mcode = 0;

                    new_icmp_hdr->un_t.echo_t.id = 0;
                    new_icmp_hdr->un_t.echo_t.seq = 0;

                    new_icmp_hdr->check = 0;
                    new_icmp_hdr->check = htons(checksum((uint16_t *)new_icmp_hdr, ICMP_HDR_SIZE));

                    memcpy(old_ip_hdr, ip_hdr, payload_size);

                    send_to_link(total_size, new_buf, interface);
                    
                    packet_s new_packet;
                    printf("%p\n", &new_packet);
                    
                    new_packet.arp_hdr = NULL;
                    new_packet.ether_hdr = new_ether_hdr;
                    new_packet.ip_hdr = new_ip_hdr;
                    new_packet.type = 1;

					continue;
                }
                ip_hdr->ttl--;

                // Facem Longest Prefix Match
                // rtable_cell va contine next_hop si interfata pe care trebuie trimis pachetul mai departe
                // Am facut o cautare binara pentru gasirea lui rtable_cell (complexitatea log(n))
                struct route_table_entry* rtable_cell = NULL;

                for (int i = 0; i < MAX_NR_OF_MASCS; i++) {
                    if (v[i].l != -1) {
                        rtable_cell = my_binary_search(rtable, ip_hdr->dest_addr & v[i].mask, v[i].l, v[i].r);
                        
                        if (rtable_cell)
                            break;
                    }
                }

                if (!rtable_cell) {
                    // Aici trebuie sa fac ICMP destination unreachable

                    printf("Am intrat in host unreachable\n");
                    
                    // Calculam noua dimensiune necesara
                    int total_hdr_size = ETHER_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE;
                    int payload_size = IP_HDR_SIZE + 8; // 8 extra bytes
                    int total_size = total_hdr_size + payload_size;

                    // Alocam spatiu suficient
                    char *new_buf = calloc(total_size, sizeof(char));

                    // Pentru usurinta, copiem ether_hdr si ip_hdr urmand sa le modificam
                    memcpy(new_buf, buf, ETHER_HDR_SIZE + IP_HDR_SIZE);

                    // Stabilim pointerii headerelor din noul pachet
                    struct ether_hdr *new_ether_hdr = (struct ether_hdr *) new_buf;
                    struct ip_hdr *new_ip_hdr = (struct ip_hdr *)((char *)new_ether_hdr + ETHER_HDR_SIZE);
                    struct icmp_hdr *new_icmp_hdr = (struct icmp_hdr *)((char *)new_ip_hdr + IP_HDR_SIZE);
                    struct ip_hdr *old_ip_hdr = (struct ip_hdr *)((char *)new_icmp_hdr + ICMP_HDR_SIZE);

                    // Modificam new_ether_hdr sa fie corect
                    memcpy(new_ether_hdr->ethr_dhost, ether_hdr->ethr_shost, 6);
                    memcpy(new_ether_hdr->ethr_shost, ether_hdr->ethr_dhost, 6);

                    // Modificam new_ip_hdr sa fie corect

                    // Noua lungime (lungimea header-ului ip + lungimea payloadului)
                    new_ip_hdr->tot_len = htons(IP_HDR_SIZE + payload_size);

                    // Punem protocolul pe 1, pentru ICMP
                    new_ip_hdr->proto = 1;

                    // Modificam adresele ip dest-sursa din header
                    new_ip_hdr->dest_addr = ip_hdr->source_addr;
                    new_ip_hdr->source_addr = my_ip_recv;

                    // Modificam checksum
                    new_ip_hdr->checksum = 0;
                    new_ip_hdr->checksum = htons(checksum((uint16_t *)new_ip_hdr, new_ip_hdr->ihl * 4));
                    
                    // Trebuie sa completam campurile din new_icmp_hdr;
                    new_icmp_hdr->mtype = ICMP_MTYPE_DESTINATION_UNREACHABLE;
                    new_icmp_hdr->mcode = 0;

                    new_icmp_hdr->un_t.echo_t.id = 0;
                    new_icmp_hdr->un_t.echo_t.seq = 0;

                    new_icmp_hdr->check = 0;
                    new_icmp_hdr->check = htons(checksum((uint16_t *)new_icmp_hdr, ICMP_HDR_SIZE));

                    memcpy(old_ip_hdr, ip_hdr, payload_size);

                    send_to_link(total_size, new_buf, interface);
                    
                    packet_s new_packet;
                    printf("%p\n", &new_packet);
                    
                    new_packet.arp_hdr = NULL;
                    new_packet.ether_hdr = new_ether_hdr;
                    new_packet.ip_hdr = new_ip_hdr;
                    new_packet.type = 1;

					continue;
                }
                
                // Modificam checksum. De aici nu mai putem sa modificam ip_hdr
                ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ihl * 4));

                // Trebuie sa setam corect adresele MAC destinatie si sursa ale pachetului (in header-ul ether_hdr)
                // Adresa MAC sender o sa fie adresa noastra MAC_send
                get_interface_mac(rtable_cell->interface, my_mac_send);
                memcpy(ether_hdr->ethr_shost, my_mac_send, 6);

                // Nu stim care este adresa MAC a urmatorului hop, deci cautam in cache
                uint8_t *mac_next_hop = get_mac_from_cache(&cache_full, rtable_cell->next_hop);

                // Daca am gasit in cache adresa MAC a urmatorului hop, completam pachetul si il trimitem
                if (mac_next_hop) {

                    memcpy(ether_hdr->ethr_dhost, mac_next_hop, 6);

                    send_to_link(len, buf, rtable_cell->interface);
                    
                    continue;
                }
                
                // Nu am gasit in cache adresa MAC de care aveam nevoie, trebuie sa trimitem un ARP REQUEST
                // Trimitem un ARP REQUEST dar, ca sa putem in viitor cand o sa primim un ARP REPLY
                // sa completam pachetul si sa il trimitem mai departe, trebuie sa salvam mai multe informatii
                // despre el

                // Facem o structura care sa tina toate informatiile necesare
                // Facem o clona a pachetului si o punem in structura
                // Adaugam structura in coada

                queue_cell_s *queue_cell = malloc(sizeof(queue_cell));

                queue_cell->len = len;
                queue_cell->rtable_cell = rtable_cell;

                // Facem o clona a pachetului, dar mai intai setam adresa MAC a urmatorului hop pe 0 pentru claritate
                memcpy(ether_hdr->ethr_dhost, zero_mac, 6);

                packet_s *packet_clone = malloc(sizeof(packet_s));
                packet_clone->type = PACKET_TYPE_IP;
                packet_clone->arp_hdr = NULL;

                packet_clone->ether_hdr = malloc(len);
                memcpy(packet_clone->ether_hdr, buf, len);
                packet_clone->ip_hdr = (struct ip_hdr *)((char *)packet_clone->ether_hdr + ETHER_HDR_SIZE);
                
                queue_cell->packet = packet_clone;
                
                // Verificam daca mai exista in coada un pachet care are nevoie de aceeasi adresa MAC destinatie (ne uitam la next_hop)
                
                if (has_queue_same_next_hop(q, queue_cell->rtable_cell->next_hop)) {
                    // Daca in coada mai exista un pachet cu aceeasi destinatie, care asteapta adresa MAC, putem sa trecem direct mai departe
                    // (dupa ce am pus pachetul in coada) pentru ca, atunci cand REPLY-ul o sa vina, o sa trimitem si acest pachet

                    queue_enq(q, queue_cell);
                    
                    continue;
                }

                queue_enq(q, queue_cell);

                // Facem si trimitem un pachet de tip ARP REQUEST
                
                my_ip_send = inet_addr(get_interface_ip(rtable_cell->interface));
                send_arp_request(packet_clone->ether_hdr->ethr_shost, my_ip_send, zero_mac, rtable_cell->next_hop, broadcast_mac, rtable_cell->interface);
                
                break;
            case PACKET_TYPE_ARP:

                if (len < ETHER_HDR_SIZE + ARP_HDR_SIZE) {
                    continue;
                }
                
                packet->arp_hdr = (struct arp_hdr *)((char *)packet->ether_hdr + ETHER_HDR_SIZE);
				packet->ip_hdr = NULL;


                struct arp_hdr *arp_hdr = packet->arp_hdr;
                
                uint16_t opcode = arp_hdr->opcode;
                uint8_t *shwa = arp_hdr->shwa; /* Sender hardware address */
                uint8_t *thwa = arp_hdr->thwa; /* Target hardware address */
                uint32_t tprotoa = arp_hdr->tprotoa; /* Target IP address */

                // Tratam fiecare caz de pachet ARP primit
                if (ntohs(opcode) == REQUEST_CODE) {
                    if (same_ip(tprotoa, my_ip_recv)) { // Eu sunt destinatia pachetului de ARP REQUEST
                        // Trebuie sa trimit un pachet ARP REPLY cu adresa mea MAC
                        // O sa trimit acelasi pachet, dar modificat

                        // Setam adresa MAC destinatie ca fiind adresa MAC a celui care a trimis pachetul ARP
                        memcpy(ether_hdr->ethr_dhost, ether_hdr->ethr_shost, 6);

                        // Setam adresa MAC sender cu propria adresa MAC
                        // Lasam aceasi adresa MAC deoarece o sa trimitem pe aceasi interfata pachetul, fiind ARP REQUEST
                        memcpy(ether_hdr->ethr_shost, my_mac_recv, 6);

                        // Setam codul pachetului pe care il intoarcem la REPLY_CODE (2)
                        arp_hdr->opcode = htons(REPLY_CODE);
                        
                        // Setam target-ul IP sa fie IP-ul celui care a trimis pachetul
                        arp_hdr->tprotoa = arp_hdr->sprotoa;
                        
                        // Setam sender-ul IP sa fie propriul IP (poate sa ramana acelasi ip, pt ca trimitem pe aceeasi interfata)
                        arp_hdr->sprotoa = my_ip_recv;

                        // Procedam la fel si cu adresele MAC
                        memcpy(thwa, shwa, 6);
                        memcpy(shwa, my_mac_recv, 6);

                        // Trimitem pachetul
                        send_to_link(len, buf, interface);

                    } else {
                        continue;
                    }

                } else if (ntohs(opcode) == REPLY_CODE) {
                    // Trebuie sa adaug in cache adresa MAC primita
                    // In cache fiecare pereche este unica
                    cache_full.cache[cache_full.nr_of_elem].ip = arp_hdr->sprotoa;
                    memcpy(cache_full.cache[cache_full.nr_of_elem].mac, arp_hdr->shwa, 6);

                    cache_full.nr_of_elem++;
                    
                    // Caut in coada toate pachetele care au next_hop adresa pachetului ARP care tocmai a venit
                    queue_cell_s *queue_cell = NULL;
                    queue temp_q = create_queue();

                    while (!queue_empty(q)) {
                        
                        queue_cell = queue_deq(q);

                        if (same_ip(queue_cell->rtable_cell->next_hop, arp_hdr->sprotoa)) {
                            // Daca am gasit un pachet care are next_hop adresa corespunzatoare,
                            // ii completam adresa MAC destinatie cu adresa MAC a pachetului care 
                            // tocmai a venit

                            memcpy(queue_cell->packet->ether_hdr->ethr_dhost, arp_hdr->shwa, 6);

                            // Acum ca am completat corect pachetul, o sa il trimitem
                            send_to_link(queue_cell->len, (char *)queue_cell->packet->ether_hdr, queue_cell->rtable_cell->interface);
                            
                        } else {
                            queue_enq(temp_q, queue_cell);
                        }
                    }

                    q = temp_q;

                } else {
                    continue;
                }

                break;
            default:
                continue;
        }

        free(packet);
    }

    free(rtable);
}
