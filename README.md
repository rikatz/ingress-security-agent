Work in progress

Please keep in mind this is a PoC and Work in progress

The idea of this project is to start a common security agent for Ingress Controllers:

* HAProxy - Using a SPOE handler
* NGINX - Using a Openresty handler


Right now, the idea is that this agent supports two kind of protections:

* Modsecurity - Using the go-modsecurity library (CGO...)
* Global rate limit - Writing sessions per vhost/source IP/etc into a k/v database and blocking when a threshold is passed

This project is based in some conversations with Manuel Alejandro - @aledbf (from ingress-nginx) and Joao Morais - @jcmoraisjr (from ingress-haproxy) and the idea is just to make a quickstart into this, and then some 'adult' can take care of the code :)

