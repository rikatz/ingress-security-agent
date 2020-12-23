## Ingress Security Agent

Work in progress

Please keep in mind this is a PoC and Work in progress

The idea of this project is to start a common security agent for Ingress Controllers:

* HAProxy - Using a SPOE handler
* NGINX - Using a Openresty handler


Right now, the idea is that this agent supports two kind of protections:

* Modsecurity - Using the go-modsecurity library (CGO...) - Ready
* Global rate limit - Writing sessions per vhost/source IP/etc into a k/v database and blocking when a threshold is passed

This project is based in some conversations with Manuel Alejandro - @aledbf (from ingress-nginx) and Joao Morais - @jcmoraisjr (from ingress-haproxy) and the idea is just to make a quickstart into this, and then some 'adult' can take care of the code :)

## Usage
This program must be compiled with ModSecurity support.

To make the life easier, I've created a Dockerfile that builds everything and leave it ready.

So, basically you need to follow those steps:
```
git clone https://github.com/rikatz/ingress-security-agent
cd ingress-security-agent
docker build -t isa:v0.1 .
docker run -p 9000:9000 -v $PWD/examples/block-localhost.conf:/rules/block-localhost.conf isa:v0.1 --modsec-rules=/rules/block-localhost.conf
```

If you want to provide different ModSecurity rules, like Coreset you can download them to any directory in your machine, adapt the configs and then use it.



## TODO

* Add some instrumentation with Prometheus (for performance testing)
* Write unit tests
* Make performance tests (a lot of them!)
