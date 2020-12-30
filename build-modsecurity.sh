#!/bin/bash
## Based in modsecurity Dockerfile 
# Ref: https://github.com/coreruleset/modsecurity-docker/blob/master/v3-nginx/Dockerfile

WORKDIR=/sources

mkdir -p ${WORKDIR} && cd ${WORKDIR}

cd ${WORKDIR}
wget --quiet https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
 && tar -xvzf ssdeep-2.14.1.tar.gz \
 && cd ssdeep-2.14.1 \
 && ./configure \
 && make install

cd ${WORKDIR}
git clone https://github.com/SpiderLabs/ModSecurity --branch v3.0.4 --depth 1 \
 && cd ModSecurity \
 && ./build.sh \
 && git submodule init \
 && git submodule update \
 && ./configure --prefix=/usr --with-yajl --with-lmdb \
 && make install

rm -rf ${WORKDIR}
