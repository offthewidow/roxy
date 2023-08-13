# Roxy

Roxy is a reverse proxy that allows to run multiple TLS services under the same ip address and port by forwarding
connections based on the [Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) extension. 
Also, it also features an HTTP server that redirects traffic from port 80 to port 443.
