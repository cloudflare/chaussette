# Chaussette

Chaussette is a proxy which takes SOCKS5 requests and proxies them to CONNECT 
over HTTP. It is designed for use with [Cloudflare](https://cloudflare.com) 
services which support 
[CONNECT over HTTP](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6) 
such as the [Privacy Edge proxies](https://www.cloudflare.com/en-gb/lp/privacy-edge/). 
Chaussette will also allow the passing of a 
[GeoHash hint](https://www.ietf.org/archive/id/draft-geohash-hint-00.html)
which will instruct the Cloudflare privacy proxy into which geography the 
requests proxied by Chaussette should egress. 


Getting Started
---------------

The proxy takes in some configuration from the command line. Environment 
Variables can also be use in place of command line options


To run with a Preshared Key passed as an Environment Variable:

```
MASQUE_PRESHARED_KEY=1234 cargo run -- --listen 127.0.0.1:1987 --proxy 
https://host.of.proxy:443 --geohash xn76cvs0-JP
```

Switches
--------
```
--listen
```
The local IP and port to listen for SOCKS5 connections on in format IP:PORT. 

```
--proxy
```
The protocol, host and port of the `privacy proxy` to make CONNECT over HTTP requests 
to in the format https://IP:PORT

```
--geohash
```
The Geohash to supply with any requests

```
--timeout
```
The timeout value of a request, specified in seconds. 
Defaults to 0 (inherit timeout from upstream)

```
--masque_preshared_key
```
If set, chaussette will supply `Proxy-Authorization: Preshared VALUE` on any HTTP 
request to the `proxy`. It can also be set using the `MASQUE_PRESHARED_KEY` env var.

```
--proxy_ca
```
If set, do not use the system CA trust store and specify a `proxy` CA to trust. 

```
--client_cert
```
If mutual TLS is used to authenticate to the `proxy` this specifies the client_cert 
to present on the CONNECT request. It can also be  set using the `CLIENT_CERT` env 
var containing the PEM certificate data. 

```
--client_key 
```
If mutual TLS is used to authenticate to the `proxy` this specifies the key to use 
for the certificate contained in `client_cert`. It can also be set using the 
`CLIENT_KEY` env var containing the PEM key data. 
