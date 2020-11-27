FROM golang:1.15.5-buster as build

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y --no-install-recommends \
    automake \
    cmake \
    curl \
    doxygen \
    g++ \
    git \
    libcurl4-gnutls-dev \
    libgeoip-dev \
    liblua5.3-dev \
    libpcre++-dev \
    libtool \
    libxml2-dev \
    make \
    ruby \
    wget \
    liblmdb0 \
    liblmdb-dev \
    libyajl2 \
    libyajl-dev \
    libfuzzy2 \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY build-modsecurity.sh /tmp/
RUN chmod +x /tmp/build-modsecurity.sh && /tmp/build-modsecurity.sh

WORKDIR /go/src/app
COPY . .
RUN go build -o /isa cmd/isa.go

FROM debian:10-slim as runtime-image
RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get install -y --no-install-recommends \
    liblmdb0 \
    libyajl2 \
    libfuzzy2 \
    libcurl3-gnutls \
    libxml2 \
    liblua5.3-0 \
    libgeoip1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/lib/libmodsecurity.so /usr/lib/
COPY --from=build /isa /usr/bin/isa

RUN /sbin/ldconfig

ENTRYPOINT ["/usr/bin/isa"]
