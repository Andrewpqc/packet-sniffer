### packte-sniffer[https://github.com/Andrewpqc/packet-sniffer]
=====================

Network sniffer for linux. Use C-Unix sockets. Support TCP, UDP, ICMP.

### Usage
``` bash
git clone https://github.com/Andrewpqc/packet-sniffer.git
&& cd packet_sniffer
&& make
&& sudo ./network_sniffer
```
you can also manage the program with the shell script `launcher.sh` by the following commands:
``` bash
git clone https://github.com/Andrewpqc/packet-sniffer.git
&& cd packet_sniffer
&& chmod +x ./launcher.sh
&& sudo ./launcher.sh
```

This program outputs the statistics of the number of various network packets on the STDOUT, and the details of each network package will be stored in `log.txt` which is under current directory.

### log example
the following is a example log case of a TCP package:
```
IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 52  Bytes(size of Packet)
   |-Identification    : 19467
   |-TTL      : 64
   |-Protocol : 6
   |-Checksum : 61622
   |-Source IP        : 127.0.0.1
   |-Destination IP   : 127.0.0.1

TCP Header
   |-Source Port      : 39668
   |-Destination Port : 1080
   |-Sequence Number    : 1047964727
   |-Acknowledge Number : 732570149
   |-Header Length      : 8 DWORDS or 32 BYTES
   |-Urgent Flag          : 0
   |-Acknowledgement Flag : 1
   |-Push Flag            : 0
   |-Reset Flag           : 0
   |-Synchronise Flag     : 0
   |-Finish Flag          : 0
   |-Window         : 359
   |-Checksum       : 65064
   |-Urgent Pointer : 0

                        DATA Dump
IP Header
    45 00 00 34 4C 0B 40 00 40 06 F0 B6 7F 00 00 01         E..4L.@.@......
    7F 00 00 01                                             ...
TCP Header
    9A F4 04 38 3E 76 AC 37 2B AA 22 25 80 10 01 67         ...8>v.7+."%�..g
    FE 28 00 00 01 01 08 0A 46 77 B9 A4 46 77 B9 7C         .(......Fw..Fw.|
Data Payload
    17 03 03 00 19 00 00 00 00 00 00 00 01 43               .............C

```