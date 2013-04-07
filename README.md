ninja_shell
===========

![Alt text](http://media.tumblr.com/bbec54d04a3712341e49f10db5d07a83/tumblr_inline_mfmd9n78p81r7if29.gif)

This is another custom raw socket shell ,
using specific tcp flags ,FIN,URG,PSH, 
too use blowfish to encrypt payloads.

*You dont can see the PORT OPEN,only you send specific flags,
to make this you can use nemesis,hping or client.c to send commands...

##to run:

on server machine:

\# gcc -o server server.c; ./server

on client machine:

\# gcc -o client client.c; ./client SERVER__IP


## Or version that make encrypted payload with blowfish
need openssl lib
on deb based linux follow:
\# apt-get install openssl-dev
on rpm based linux follow:
\# yum install openssl-devel


on server machine:

\# gcc -o server_blowfish server_blowfish.c -lssl -lcrypto; ./server

on client machine:

\# gcc -o client_blowfish client_blowfish.c -lssl -lcrypto; ./client SERVER__IP






