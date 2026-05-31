FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Makefile ./Makefile
COPY src ./src
RUN make

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1337 ctf

WORKDIR /home/ctf
COPY --from=build /public/Siuuuuuuu ./Siuuuuuuu
COPY flag.txt ./flag.txt

RUN chmod 755 ./Siuuuuuuu && chmod 444 ./flag.txt

USER ctf
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/Siuuuuuuu,stderr"]
