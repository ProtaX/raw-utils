# raw-utils
Exaple progams using raw sockets.
# rping
rping is written on golang, it is analog to Linux`s ping command. Works both on Windows (not sure if it is correct) and Linux.
# rsniffer
Simple tcp, udp, icmp sniffer. Written on C, works only on Linux.
# Build
Both folders contain Makefile, so run:
```
cd rping && make
```
In order to use raw sockets, programs should be ran under su, for example:
```
sudo ./rping.out -c 5 -ip 127.0.0.1 -payload 123321
```
