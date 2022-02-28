#include <queue.h>
#include "skel.h"
#include <string.h>

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

// functia care parseaza tabela de rutare, din fisierul dat
void read_rtable(struct route_table_entry* rtable, FILE* rtable_file, int nr_of_entries) {
	
	char* p;
	char s[100];
	
	for(int i = 0; i < nr_of_entries; i++) {
		fgets(s, 100, rtable_file);
		p = strtok(s, " ");
		rtable[i].prefix = inet_addr(p);

		p = strtok(NULL, " ");
		rtable[i].next_hop = inet_addr(p);

		p = strtok(NULL, " ");
		rtable[i].mask = inet_addr(p);

		p = strtok(NULL, " ");
		rtable[i].interface = atoi(p) ;
	}
}

// functia din laborator care cauta cel mai bun route
struct route_table_entry *get_best_route(__u32 dest_ip, struct route_table_entry *rtable, int nr_of_entries) {
	int best_entry = -1;
	for (int i = 0; i < nr_of_entries; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			if (best_entry == -1 || ntohl(rtable[i].mask) > ntohl(rtable[best_entry].mask)) {
				best_entry = i;
			}
		}
	}

	if (best_entry == -1) {
		printf("Nu s-a gasit adresa la care sa trimit pachetul\n");
		return NULL;
	}

	return &rtable[best_entry];
}

// functia care cauta MAC-ul next_hop-ului
struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry *arp_table, int arp_table_len) {
    for (int i = 0; i < arp_table_len; i++) {
    	if (ip == arp_table[i].ip) {
    		return &arp_table[i];
    	}
    }
    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc, nr_of_entries = 0;
	char s[100];
	struct route_table_entry *rtable;
	struct arp_entry *arp_table;
	int arp_table_len = 0;
	uint8_t mac_unknown[6];
	hwaddr_aton("ff:ff:ff:ff:ff:ff", mac_unknown);
	uint8_t k[6];

	queue package_queue = queue_create();

	init(argc - 2, argv + 2);

	FILE* rtable_file = fopen(argv[1], "r");

	// se afla numarul de intrari din tabela de rutare
	while(fgets(s, 100, rtable_file)) {
		nr_of_entries ++;
	}
	fseek ( rtable_file , 0 , SEEK_SET);

	// se parseaza tabela de rutare
	rtable = malloc(sizeof(struct route_table_entry) * nr_of_entries);
	read_rtable(rtable, rtable_file, nr_of_entries);

	arp_table = malloc(sizeof(struct  arp_entry) * 100);

	while (1) {
		// se primeste urmatorul pachet
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct icmphdr* icmp_hdr;
		struct iphdr *ip_hdr;

		// daca pachetul este de tip IP
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {

			ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			icmp_hdr = parse_icmp(m.payload);

			// daca pachetul este de tip ICMP ECHO, trimite un raspuns 
			if (icmp_hdr!= NULL) {
				if (icmp_hdr->type == ICMP_ECHO) {
					if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
						send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
						ICMP_ECHOREPLY, 0, m.interface, ip_hdr->id, icmp_hdr->un.echo.sequence);
						continue;
					}
				}
			}

			// daca TTL este <=1, trimite mesaj sursei
			if (ip_hdr->ttl <= 1) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
							ICMP_TIME_EXCEEDED, 0, m.interface, ip_hdr->id, 1);
				continue;
			}

			// se verifica checksum-ul, iar daca este gresit se arunca pachetul
			if(ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				printf("wrong checksum!");
			} else {
				ip_hdr->ttl -= 1;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				// se cauta cea mai buna cale pentru a trimite pachetul
				struct route_table_entry* best_route = get_best_route(ip_hdr->daddr, rtable, nr_of_entries);
				if (best_route == NULL) {
					// daca nu se gaseste niciuna, trimite un mesaj de eroare sursei si arunca pachetul
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
							ICMP_DEST_UNREACH, 0, m.interface, ip_hdr->id, 1);
				} else {
					// se cauta adresa MAC a next_hop-ului in tabela ARP
					struct arp_entry* curr_arp_entry = get_arp_entry(ip_hdr->daddr, arp_table, arp_table_len);

					// daca nu este in tabela ARP, se trimite un ARP_REQUEST catre hext_hop,
					// iar pachetul se pastreaza intr-o coada.
					if (curr_arp_entry == NULL) {
						packet n;
						memcpy(&n, &m, sizeof(packet));
						queue_enq(package_queue, &n);

						get_interface_mac(best_route->interface, k);
						memcpy(eth_hdr->ether_shost, k, 6);
						memcpy(eth_hdr->ether_dhost, mac_unknown, 6);
						eth_hdr->ether_type = htons(ETHERTYPE_ARP);
						
						send_arp(best_route->next_hop, inet_addr(get_interface_ip(best_route->interface)), eth_hdr, best_route->interface, htons(ARPOP_REQUEST));
					} else {
						// daca adresa MAC este cunoscuta, se trimite pachetul mai departe
						get_interface_mac(best_route->interface, k);

						memcpy(eth_hdr->ether_shost, k, 6);
						memcpy(eth_hdr->ether_dhost, curr_arp_entry->mac, 6);
						send_packet(best_route->interface, &m);
					}
				}
			}

		} else {
			// daca pachetul este de tip ARP
			struct arp_header* arp_hdr;
			arp_hdr = parse_arp(m.payload);
			if (arp_hdr != NULL) {
				// daca este de tip ARP_REQUEST se trimite inapoi sursei un pachet ARP_REPLY
				// ce contine adresa MAC a routerului, pentru a putea primi pachete de la sursa
				if (arp_hdr->op == htons(ARPOP_REQUEST)) {
					get_interface_mac(m.interface, k);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, k, 6);
					send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
				
				// daca este de tip ARP_REPLY
				} else if (arp_hdr->op == htons(ARPOP_REPLY)) {
					// se adauga in tabela ARP un entry cu adresele IP si MAC a sursei
					arp_table_len++;
					arp_table[arp_table_len - 1].ip = arp_hdr->spa;
					memcpy(arp_table[arp_table_len - 1].mac, arp_hdr->sha, 6);

					// se scoate un pachet din coada de asteptare
					packet *first_packet;
					if (!queue_empty(package_queue)) {
					first_packet = queue_deq(package_queue);

					eth_hdr = (struct ether_header *)first_packet->payload;
					ip_hdr = (struct iphdr *)(first_packet->payload + sizeof(struct ether_header));
					
					int x = get_best_route(ip_hdr->daddr, rtable, nr_of_entries)->interface;

					get_interface_mac(x, k);

					// se modifica adresele MAC si se trimite pachetul
					memcpy(eth_hdr->ether_shost, k, 6);
					memcpy(eth_hdr->ether_dhost, arp_table[arp_table_len - 1].mac, 6);
					send_packet(x, first_packet);
					}
				}
			}
		}
	}
	
}
