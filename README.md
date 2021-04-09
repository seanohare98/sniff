# Packet Sniffer (for basic intrusion detection)
#### Written for CSCI4430 (Data Communication and Computer Networks)
## Dependencies
Be sure to have lpcap header files
```
sudo apt-get install libpcap-dev
```
## Building
```
make
```
## Build Output
Executables for the sniffer and a test attack program
### Usage
```
./myids [online|offline] <arg> <hh_thresh> <h_pscan_thresh> <v_pscan_thresh> <epoch>
```
<b>arg</b> is the interface name for online mode or the <b>.pcap</b> file name for offline mode
