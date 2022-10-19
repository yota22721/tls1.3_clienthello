# tls1.3_clienthello
Simple implementation of tls.13 ClientHello for learning purposes

This program can only work on Linux
<br>
<br>
note :  Cryptographic  algorithms are not impemented.

Server
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout myPKey.pem \
    -out myCert.crt \
    -subj '/CN=JP'
openssl s_server -accept 4043 -cert myCert.crt -key myPKey.pem
```

Client 
```
./ch
```

Client Hello
```
[*]Start connecting...
[*]connection succeeded!
[*]sent buffer...
server response :  16 03 03 00 5b 02 00 00 57 03 03 56 fe b3 ac 38 d5 df d1 4b b0
 3b 0a 62 b1 48 a4 96 e8 16 e4 52 4b 02 e3 df 6f 51 05 8f 1a bb 9a 01 00 13 02 00 
 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 72 84 a0 50 0c 67 e3 c3 da 35 31 
 7e 71 89 a4 02 69 bc 03 b8 26 03 c5 ca 93 84 98 77 f2 77 df 74 14 03 03 00 01 01 
 17 03 03 00 17 bc f8 00 22 5e 21 30 2e 18 54 f6 ed 60 dc .....
```

From server hello ,
```
00 2b 00 02 03 04
``` 
These 6 bytes prove the connection is tls1.3 !!

## reference
[The Illustrated TLS 1.3 Connection Every byte explained and reproduced](https://tls13.xargs.org/)

[The Transport Layer Security (TLS) Protocol Version 1.3 - RFC 8446 ](https://datatracker.ietf.org/doc/html/rfc8446)

[Elliptic Curves for Security - RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)

[Pure Python Implementation Of TLS 1.3](https://github.com/IdoBn/tls1.3)
