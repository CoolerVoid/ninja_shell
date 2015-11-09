ninja_shell v2.0
================

![Alt text](https://github.com/CoolerVoid/ninja_shell/blob/master/docs/img/giphy.gif?raw=true)

This is a custom raw socket shell aka port knoking, https://en.wikipedia.org/wiki/Port_knocking
using specific tcp flags ,FIN,URG,PSH and use AES 256 cipher at communication.

*You dont can see the PORT OPEN,only you send specific flags,
to make this you can use nemesis,hping or client.c to send commands...

##to run you need use root because raw socket need:
\# make

on server machine:

\#  ./bin/server

on client machine:

\# ./bin/client SERVER__IP


## if return errors at make, you need openssl lib
So to get this lib you can follow this examples:

on deb based linux follow:
\# apt-get install openssl-dev
on rpm based linux follow:
\# yum install openssl-devel


##Diagram how works
![Alt text](https://github.com/CoolerVoid/ninja_shell/blob/master/docs/img/diagram.png?raw=true)




