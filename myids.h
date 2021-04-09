#ifndef MYIDS_H
#define MYIDS_H
#define ETH_HDR_LEN 14

void printHeavyHitter(double pkt_ts, unsigned int src_ip);
void printHorizontalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_port);
void printVerticalScan(double pkt_ts, unsigned int src_ip, unsigned int dst_port);
void printAggregateTraffic(unsigned int tot_packets, unsigned int tot_ip_packets, unsigned int tot_valid_ip_packets, unsigned int tot_ip_payload_size, unsigned int tot_tcp_packets, unsigned int tot_udp_packets, unsigned int tot_icmp_packets);
unsigned short in_cksum(unsigned short *addr, int len);
void sniff(char *mode, char *arg, unsigned int hh_thresh, unsigned int h_pscan_thresh, unsigned int v_pscan_thresh, unsigned int epoch);
#endif
