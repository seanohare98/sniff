#include <iostream>
#include <map>
#include <string>
#include <iterator>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "myids.h"

std::map<unsigned int, unsigned long long> hh_map;                                            // <src_ip, payload_size>
std::map<std::pair<unsigned int, unsigned int>, std::vector<unsigned int> > h_pscan_map;      // <<src_ip, dst_port>, vec<dst_ip>>
std::map<std::pair<unsigned int, unsigned int>, std::vector<unsigned int> > v_pscan_map;      // <<src_ip, dst_ip>, vec<dst_port>>
std::vector<unsigned int> hh_reports;
std::vector<std::pair<unsigned int, unsigned int> > h_pscan_reports;
std::vector<std::pair<unsigned int, unsigned int> > v_pscan_reports;

void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

void checkHeavyHitter(double pkt_ts, unsigned int src_ip, unsigned int payload, unsigned int hh_thresh) {
    // IP not present in map
    if (hh_map.find(src_ip) == hh_map.end() ) {
        hh_map[src_ip] = payload;       // Add IP to map w/ payload size
    }
    else {
        hh_map[src_ip] += payload;      // Increment payload
    }
    
    // See if already reported intrusion for this IP
    bool reported = std::find(hh_reports.begin(), hh_reports.end(), src_ip) != hh_reports.end();
    
    // Report intrusion if over threshold
    if (hh_map[src_ip] > hh_thresh * 1000000 && !reported) {
        printHeavyHitter(pkt_ts, src_ip);
        hh_reports.push_back(src_ip);
    }
}

void checkHorizontalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_port, unsigned int dst_ip, unsigned int h_pscan_thresh) {
    // (IP, Port) pair not present in map
    if (h_pscan_map.find(std::make_pair(src_ip, dst_port)) == h_pscan_map.end()) {
        std::vector<unsigned int> v;
        v.push_back(dst_ip);
        h_pscan_map[std::make_pair(src_ip, dst_port)] = v; 
    }
    else {
        if (std::find(h_pscan_map[std::make_pair(src_ip, dst_port)].begin(), h_pscan_map[std::make_pair(src_ip, dst_port)].end(), dst_ip) == h_pscan_map[std::make_pair(src_ip, dst_port)].end()) {
            h_pscan_map[std::make_pair(src_ip, dst_port)].push_back(dst_ip);
        }
        
        bool reported = std::find(h_pscan_reports.begin(), h_pscan_reports.end(), std::make_pair(src_ip, dst_port)) != h_pscan_reports.end();

        if (h_pscan_map[std::make_pair(src_ip, dst_port)].size() > h_pscan_thresh && !reported) {
            printHorizontalScan(pkt_ts, src_ip, dst_port);
            h_pscan_reports.push_back(std::make_pair(src_ip, dst_port));
        }  
    }
}

void checkVerticalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_ip, unsigned int dst_port, unsigned int v_pscan_thresh) {
    if (v_pscan_map.find(std::make_pair(src_ip, dst_ip)) == v_pscan_map.end()) {
        std::vector<unsigned int> v;
        v.push_back(dst_port);
        v_pscan_map[std::make_pair(src_ip, dst_ip)] = v; 
    }
    else {
        if (std::find(v_pscan_map[std::make_pair(src_ip, dst_ip)].begin(), v_pscan_map[std::make_pair(src_ip, dst_ip)].end(), dst_port) == v_pscan_map[std::make_pair(src_ip, dst_ip)].end()) {
            v_pscan_map[std::make_pair(src_ip, dst_ip)].push_back(dst_port);
        }
        
        bool reported = std::find(v_pscan_reports.begin(), v_pscan_reports.end(), std::make_pair(src_ip, dst_ip)) != v_pscan_reports.end();

        if (v_pscan_map[std::make_pair(src_ip, dst_ip)].size() > v_pscan_thresh && !reported) {
            printVerticalScan(pkt_ts, src_ip, dst_ip);
            v_pscan_reports.push_back(std::make_pair(src_ip, dst_ip));
        }  
    }
}

void printHeavyHitter(double pkt_ts, unsigned int src_ip) {
    printf("At timestamp %lf: A heavy hitter is detected\n"
        "- source IP: %d.%d.%d.%d\n",
        pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,
        (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff);    
}

void printHorizontalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_port) {
    printf("At timestamp %lf: A horizontal portscan is detected\n"
        "- source IP: %d.%d.%d.%d, port: %hu\n",
        pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,
        (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
        dst_port);
}

void printVerticalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_ip) {
    printf("At timestap %lf: A vertical portscan is dectected\n"
        "- source IP: %d.%d.%d.%d, target IP: %d.%d.%d.%d\n",
        pkt_ts, src_ip & 0xff, (src_ip >> 8) & 0xff,
        (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff,
        dst_ip & 0xff, (dst_ip >> 8) & 0xff,
        (dst_ip >> 16) & 0xff, (dst_ip >> 24) & 0xff);
}

void printAggregateTraffic(unsigned int tot_packets, unsigned int tot_ip_packets, unsigned int tot_valid_ip_packets, unsigned int tot_ip_payload_size, unsigned int tot_tcp_packets, unsigned int tot_udp_packets, unsigned int tot_icmp_packets) {
    printf("Total number of observed packets: %u\n", tot_packets);
    printf("Total number of observed IP packets: %u\n", tot_ip_packets);
    printf("Total number of observed valid IP packets: %u\n", tot_valid_ip_packets);
    printf("Total IP payload size: %u bytes\n", tot_ip_payload_size);
    printf("Total number of TCP packets: %u\n", tot_tcp_packets);
    printf("Total number of UDP packets: %u\n", tot_udp_packets);
    printf("Total number of ICMP packets: %u\n", tot_icmp_packets);
}

unsigned short in_cksum(unsigned short *addr, int len) { 
	int nleft = len;
    unsigned short *w = addr;
    int sum = 0;
    unsigned short answer = 0;
    while(nleft > 1) {
        sum += *w++;
		nleft -= 2; 
	}
	if(nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w; sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
	answer = ~sum;
	return (unsigned short)answer;
}

void sniff(char* mode, char* arg, unsigned int hh_thresh, unsigned int h_pscan_thresh, unsigned int v_pscan_thresh, unsigned int epoch_length) {
	pcap_t* pcap;
	char errbuf[256];
	struct pcap_pkthdr hdr;
	const u_char* pkt;			    // raw packet
	double pkt_ts;				    // raw packet timestamp
    unsigned int pkt_payload_size;

	struct ether_header* eth_hdr = NULL;
	struct ip* ip_hdr = NULL;
	struct tcphdr* tcp_hdr = NULL;
    struct udphdr* udp_hdr = NULL;

	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;

	// Relevant traffic data
	unsigned int tot_packets = 0;
	unsigned int tot_ip_packets = 0;
	unsigned int tot_valid_ip_packets = 0;
	unsigned int tot_ip_payload_size = 0;
	unsigned int tot_tcp_packets = 0;
	unsigned int tot_udp_packets = 0;
	unsigned int tot_icmp_packets = 0;
    
    // Initial timestamp
    double epoch_start = -1;
	
    // Pcap open
	if (strcmp(mode, "online") == 0) {
		if ((pcap = pcap_open_live(arg, 1500, 1, 1000, errbuf)) == NULL) {
			std::cout << "ERR: cannot open " << arg << " (" << errbuf << ")" << std::endl;
			exit(-1);
		}
	}
	else if (strcmp(mode, "offline") == 0) {
		if ((pcap = pcap_open_offline(arg, errbuf)) == NULL) {
			std::cout << "ERR: cannot open " << arg << " (" << errbuf << ")" << std::endl;
			exit(-1);
		}	
	}
	else {
		exit(-1);
	}	

	while (1) {
		if ((pkt = pcap_next(pcap, &hdr)) != NULL) {
            // Get timestamp
			pkt_ts = (double)hdr.ts.tv_usec / 1000000 + hdr.ts.tv_sec;
		     
            // First packet (begin epoch counter) 
            if (epoch_start < 0) {
                epoch_start = pkt_ts;
            } 

            // Reached new epoch
            if (pkt_ts - epoch_start >= epoch_length) {
                // Log aggregate traffic 
                printAggregateTraffic(tot_packets, tot_ip_packets, tot_valid_ip_packets, tot_ip_payload_size, tot_tcp_packets, tot_udp_packets, tot_icmp_packets);
                
                // Reset counters 
                epoch_start = pkt_ts;
                tot_packets = 0;
                tot_ip_packets = 0;
                tot_valid_ip_packets = 0;
                tot_ip_payload_size = 0;
                tot_tcp_packets = 0;
                tot_udp_packets = 0;
                tot_icmp_packets = 0;            
                
                // Reset intrusion data
                hh_map.clear();
                h_pscan_map.clear();
                v_pscan_map.clear();
                hh_reports.clear();
                h_pscan_reports.clear();
                v_pscan_reports.clear();
            }
            
            // Increment counter (total packets)
            tot_packets++;

			// Parse the headers
			eth_hdr = (struct ether_header*)pkt;
			switch (ntohs(eth_hdr->ether_type)) {
				case ETH_P_IP:						// IP Packets (no VLAN header)
					ip_hdr = (struct ip*)(pkt + ETH_HDR_LEN);
					break;
				case 0x8100:						// with VLAN header (with 4 bytes)
					ip_hdr = (struct ip*)(pkt+ ETH_HDR_LEN + 4);
					break;
			}			
			
			// If IP header is NULL (not IP or VLAN), continue.
			if (ip_hdr == NULL) {
				continue;
			}

            //Increment counter (total ip packets)
            tot_ip_packets++;

			// If valid IP header
			if (in_cksum((unsigned short*)ip_hdr, sizeof(*ip_hdr)) == 0) {
                // Increment counter (total valid ip packets)
                tot_valid_ip_packets++;
                
                // Increment counter (total ip payload size)
                pkt_payload_size = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
                tot_ip_payload_size += pkt_payload_size;

			    // IP addresses are in network-byte order
			    src_ip = ip_hdr->ip_src.s_addr;
			    dst_ip = ip_hdr->ip_dst.s_addr;
		        
                // Check protocol type
                switch(ip_hdr->ip_p) {
                    case IPPROTO_TCP:
                        tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2));
                        src_port = ntohs(tcp_hdr->source);
                        dst_port = ntohs(tcp_hdr->dest);			

                        // Intrusion detection (hh, v_pscan, h_pscan)
                        checkHeavyHitter(pkt_ts, src_ip, pkt_payload_size, hh_thresh);
				        checkHorizontalScan(pkt_ts, src_ip, dst_port, dst_ip, h_pscan_thresh);
                        checkVerticalScan(pkt_ts, src_ip, dst_ip, dst_port, v_pscan_thresh);
                        fflush(stdout);

                        // Increment counter (total tcp packets)
                        tot_tcp_packets++;
                        break;
                    case IPPROTO_UDP:
                        udp_hdr = (struct udphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl << 2));
                        src_port = ntohs(udp_hdr->source);
                        dst_port = ntohs(udp_hdr->dest);
                        
                        // Intrusion detection (hh, v_pscan, h_pscan)
                        checkHeavyHitter(pkt_ts, src_ip, pkt_payload_size, hh_thresh);
                        checkHorizontalScan(pkt_ts, src_ip, dst_port, dst_ip, h_pscan_thresh);
                        checkVerticalScan(pkt_ts, src_ip, dst_ip, dst_port, v_pscan_thresh);
                        fflush(stdout);

                        // Increment counter (total udp packets)
                        tot_udp_packets++;
                        break;
                    case IPPROTO_ICMP:
                        // Intrusion detection (hh only)
                        checkHeavyHitter(pkt_ts, src_ip, pkt_payload_size, hh_thresh);
                        fflush(stdout);

                        // Increment counter (total icmp packets)
                        tot_icmp_packets++;
                        break;
                    default:
                        break;
                }	
		    }
        }
        // pcap_next() is NULL
        else {
            // If offline mode, reached EOF
	        if (strcmp(mode, "offline") == 0) 
                exit(0);
        }
    }
	pcap_close(pcap);
}

int main(int argc, char** argv) {
    // Input validation
    if (argc != 7) {
        std::cout << "Usage: ./myids [online|offline] <arg> <hh_thresh> <h_pscan_thresh> <v_pscan_thresh> <epoch>" << std::endl;
        return -1;
    }

    char* mode = argv[1];
    char* arg = argv[2];
    unsigned int hh_thresh = atoi(argv[3]);
    unsigned int h_pscan_thresh = atoi(argv[4]);
    unsigned int v_pscan_thresh = atoi(argv[5]);
    unsigned int epoch = atoi(argv[6]);

    // Run sniffer
    sniff(mode, arg, hh_thresh, h_pscan_thresh, v_pscan_thresh, epoch);
    return 0;
}
