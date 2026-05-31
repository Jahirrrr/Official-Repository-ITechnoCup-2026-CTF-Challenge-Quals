FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Makefile .
COPY src ./src
RUN make

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 ctf

WORKDIR /home/ctf
COPY --from=build /public/planetarium ./planetarium
COPY flag.txt /flag.txt

RUN chmod 0555 ./planetarium && chmod 0444 /flag.txt
USER ctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/planetarium,stderr"]
