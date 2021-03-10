ninja_shell v2.1
==================

![Alt text](https://github.com/CoolerVoid/ninja_shell/blob/master/docs/img/giphy.gif?raw=true)

Raw socket shell with AES256-GCM, using Port Knocking technique( https://en.wikipedia.org/wiki/Port_knocking )
using specific TCP flags, FIN, URG, and PSH.



## Raw socket?

 Raw mode is there to bypass some of the ways your computer handles TCP/IP. Rather than going through the typical layers of encapsulation/decapsulation that the TCP/IP stack on the kernel does, you pass the packet to the application that needs it. No TCP/IP processing -- so it's not a processed packet. It's a raw packet. The application that's using the packet is now responsible for stripping off the headers, analyzing the packet, all the stuff that the TCP/IP stack in the kernel does typically for you.

A raw socket is a socket that takes packets, bypasses the standard TCP/IP processing, and sends them to the application that wants them.

Unless you're a programmer, a kernel hacker, or really into security, you will most likely not need to deal much with these. But it's good to know what they are if you find yourself in one of the above scenarios. 

https://en.wikipedia.org/wiki/Raw_socket


## Install OpenSSL lib

Deb based Linux follow:
```
\# apt-get install openssl-dev
```
or
```
\# apt-get install libssl or ssl-dev
```

on rpm based Linux follow:
```
\# yum install openssl-devel
```

## To run, you need to use root because raw socket needs:

To compile
```
\# make
```
on server machine:
```
\# bin/server
```
on the client machine:
```
\# bin/client the_SERVER_IP_addr (note  don't use  localhost  or 127.0.0.1 put real IP address, this version support only IPV4)
```
To change keys edit /src/server.c and /src/client.c, and compile...



