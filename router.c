#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>	
#include <string.h>

static struct trie_node *route_trie;
static u_int32_t route_count;


// aici e posibil sa fie ceva gresit
int populate_trie(const char *path, struct trie_node *root) {
    FILE *fp;
    char line[64];
    int entries = 0;

    // Încercăm să deschidem fișierul și verificăm dacă operația a reușit.
    fp = fopen(path, "r");
    if (!fp) {
        perror("Nu se poate deschide fișierul");
        return -1; // Returnăm -1 pentru a indica o eroare.
    }

    // Citim fiecare linie din fișier.
    while (fgets(line, sizeof(line), fp) != NULL) {
        struct route_table_entry *new = malloc(sizeof(struct route_table_entry));
        if (!new) {
            perror("Alocare memorie eșuată");
            fclose(fp);
            return -1;
        }
        
        char *token;
        int tokenIndex = 0;
        token = strtok(line, " .");

        // Parsăm fiecare parte a liniei.
        while (token != NULL && tokenIndex < 13) {
            unsigned char value = (unsigned char)atoi(token);

            if (tokenIndex < 4) {
                *(((unsigned char *) &new->prefix) + tokenIndex) = value;
            } else if (tokenIndex < 8) {
                *(((unsigned char *) &new->next_hop) + (tokenIndex % 4)) = value;
            } else if (tokenIndex < 12) {
                *(((unsigned char *) &new->mask) + (tokenIndex % 4)) = value;
            } else {
                new->interface = atoi(token);
            }
            
            token = strtok(NULL, " .");
            tokenIndex++;
        }

        // Inserăm intrarea în trie.
        insert_node(root, new);
        entries++;
    }

    // Închidem fișierul după ce am terminat cu el.
    fclose(fp);
    return entries; // Returnăm numărul de intrări adăugate în trie.
}

struct route_table_entry *next_hop(uint32_t dest_ip)
{
	struct trie_node *node_found = search(route_trie, dest_ip);

	if (node_found != NULL)
		return node_found->entry;
	else
		return NULL;
}


void create_ICMP_message(char* buf, size_t *len, int interface, uint8_t type, uint8_t code) {
    // Presupunem că buffer-ul este suficient de mare pentru a conține un mesaj ICMP complet.
    struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_START);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ICMP_START);

    // Copiem partea de IP header în zona de date ICMP, pentru a fi inclusă ca date în mesajul ICMP.
    memcpy(buf + ICMP_START + sizeof(struct icmphdr), ip_hdr, ICMP_DATA_SIZE);

    // Actualizăm header-ul IP
    ip_hdr->daddr = ip_hdr->saddr; // Schimbăm adresa de destinație cu cea de sursă.
    ip_hdr->saddr = inet_addr(get_interface_ip(interface)); // Setăm noua adresă de sursă.
    ip_hdr->ttl = TTL; // Setăm TTL-ul.
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_DATA_SIZE); // Actualizăm lungimea totală.
    ip_hdr->protocol = IPPROTO_ICMP; // Specificăm că folosim protocolul ICMP.

    // Recalculăm checksum-ul pentru header-ul IP.
    ip_hdr->check = 0; // Înainte de recalculare, checksum-ul trebuie setat pe 0.
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    // Construim header-ul ICMP.
    memset(icmp_hdr, 0, sizeof(struct icmphdr)); // Inițializăm header-ul ICMP cu 0.
    icmp_hdr->type = type; // Setăm tipul mesajului ICMP.
    icmp_hdr->code = code; // Setăm codul mesajului ICMP.

    // Calculăm checksum-ul pentru header-ul ICMP.
    icmp_hdr->checksum = 0; // Înainte de recalculare, checksum-ul trebuie setat pe 0.
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + ICMP_DATA_SIZE));

    // Setăm noua lungime a mesajului.
    *len = sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_DATA_SIZE;
}

void forward_package(char* buf, size_t len, int interface) {
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_START);

    // Verificăm TTL-ul și generăm un mesaj ICMP dacă este necesar.
    if (ip_hdr->ttl <= 1) {
        create_ICMP_message(buf, &len, interface, TIME_EXCEEDED_TYPE, TIME_EXCEEDED_CODE);
        send_to_link(interface, buf, len);
        return;
    }

    // Verificăm checksum-ul IPv4.
    uint16_t received_checksum = ip_hdr->check;
    ip_hdr->check = 0; // Setăm checksum-ul la 0 pentru a recalcula.
    if (received_checksum != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
        // Dacă checksum-ul nu este valid, pachetul este descărcat.
        return;
    }

    // Scădem TTL-ul și recalculăm checksum-ul.
    ip_hdr->ttl--;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    // Determinăm următoarea oprire pe baza adresei de destinație.
    struct route_table_entry *next = next_hop(ntohl(ip_hdr->daddr));
    if (next == NULL) {
        create_ICMP_message(buf, &len, interface, DESTINATION_UNREACHABLE_TYPE, DESTINATION_UNREACHABLE_CODE);
        send_to_link(interface, buf, len);
        return;
    }

    // Actualizăm adresa MAC a sursei pentru header-ul Ethernet și redirecționăm pachetul.
    get_interface_mac(next->interface, eth_hdr->ether_shost);
    send_to_link(next->interface, buf, len);
}

void router_as_destination(char* buf, size_t len, int interface) {
    struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_START);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ICMP_START);

    // Verificăm checksum-ul ICMP.
    uint16_t old_checksum = icmp_hdr->checksum;
    icmp_hdr->checksum = 0; // Resetează checksum-ul pentru recalculare.
    uint16_t new_checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));
    if (old_checksum != new_checksum) {
        // Dacă checksum-ul nu corespunde, ignorăm pachetul.
        return;
    }

    // Inversăm adresele IP sursă și destinație pentru a pregăti răspunsul.
    uint32_t temp = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = temp;

    // Recalculăm checksum-ul IP după modificarea header-ului.
    ip_hdr->check = 0; // Resetează checksum-ul pentru recalculare.
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    // Modificăm header-ul ICMP pentru a trimite un răspuns Echo Reply.
    icmp_hdr->type = ECHO_REPLY_TYPE;
    icmp_hdr->code = ECHO_REPLY_CODE; // Codul pentru Echo Reply este întotdeauna 0.
    icmp_hdr->checksum = 0; // Resetează checksum-ul pentru recalculare.
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

    // Redirecționăm pachetul înapoi la sursă.
    forward_package(buf, len, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_trie = new_trie_node();
	route_count = populate_trie(argv[1], route_trie);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		if (ntohs(eth_hdr->ether_type) == IP_ETH) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + IP_START);
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				router_as_destination(buf, len, interface);
			} else {
				forward_package(buf, len, interface);
			}
		}
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}

