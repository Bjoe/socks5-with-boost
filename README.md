# Socks 5 with boost asio for C++14

just a simple implementation of socks 5 to test some stuff, for example TCP splice.
See https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future/

Not usable yet, more improvement are needed !

## using

start two docker instances
Docker 1:
 $ SOCKS5_SERVER=172.17.0.1:1080 SOCKS_AUTOADD_LANROUTES=no socksify socat tcp-connect:172.17.0.3:12345 stdin
 
Docker 2:
 $ socat tcp-listen:12345 stdio

on the host:
 $ sudo bs5 --relay sockmap -n 172.17.0.1 -s 172.17.0.1
