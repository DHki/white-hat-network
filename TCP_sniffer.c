#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "myheader.h"

//processing function handle captured packet
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet){
    struct ethheader* eth = (struct ethheader*) packet;

    if(ntohs(eth->ether_type) == 0x800){ // when IPv4 packet
        struct ipv4header* ip = (struct ipv4header*)(packet + sizeof(struct ethheader));

        if(ip->iph_protocol == 6){ // when protocol is TCP
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            printf("----- Packet Header -----\n");
            printf("[Ethernet header]\n");
            printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("\n");

            printf("[IP header]\n");
            printf("source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("destination IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("\n");

            printf("[TCP header]\n");
            printf("source port: %d\n", ntohs(tcp->tcp_sport));
            printf("destination port: %d\n", ntohs(tcp->tcp_dport));
            printf("\n");

            char* payload = (char*)(packet + 14 + (ip->iph_ihl * 4) + (tcp->tcp_hlen * 4));
            unsigned int payload_len = ip->iph_len - ip->iph_ihl * 4 - tcp->tcp_hlen * 4;
            
            printf("----- Message -----\n");
            int i = 0;
            for(;i < 64; i++){
                
                if (payload[i] >= 32 && payload[i] <= 126) {
                printf("%c", payload[i]);
                } else {
                    printf(".");
                }

                if((i + 1) % 16 == 0){printf("\n");}
            }
            printf("\n\n");

        }
    }
    
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE]; // error message buffer
    pcap_t* handle; // packet's session
    struct bpf_program fp;

    char filter[] = "tcp"; // packet filter
    handle = pcap_open_live("eth0", BUFSIZ, 1, 500, errbuf); // make session
    pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN); // filter compile

    // start capturing
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}