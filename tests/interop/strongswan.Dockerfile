# strongSwan with ML-KEM, used as the interoperability test client.
FROM debian:trixie
ARG STRONGSWAN_VERSION=6.1.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev ca-certificates curl bzip2 iproute2 iputils-ping
RUN curl -fsSL https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2 | tar xj -C /tmp \
 && cd /tmp/strongswan-${STRONGSWAN_VERSION} \
 && ./configure --prefix=/usr --sysconfdir=/etc --enable-swanctl --enable-vici \
      --enable-openssl --enable-ml --disable-stroke \
 && make -j"$(nproc)" && make install && rm -rf /tmp/strongswan-*
