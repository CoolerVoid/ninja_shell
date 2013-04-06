ninja_shell
===========

![Alt text](http://media.tumblr.com/bbec54d04a3712341e49f10db5d07a83/tumblr_inline_mfmd9n78p81r7if29.gif)

This is another custom raw socket shell ,
using specific tcp flags ,FIN,URG,PSH...

*You dont can see the PORT OPEN,only you send specific flags,
to make this you can use nemesis,hping or client.c to send commands...

to run:

on client machine:
\# gcc -o client client.c

on server machine:
\# gcc -o server server.c




