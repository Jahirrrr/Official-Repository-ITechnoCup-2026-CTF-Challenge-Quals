FROM ubuntu:24.04 AS build

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential make \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile indonesia.c ./
RUN make

FROM ubuntu:24.04

RUN apt-get update \
	&& apt-get install -y --no-install-recommends socat \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd -m -u 1337 ctf

WORKDIR /home/ctf
COPY --from=build /src/indonesia ./indonesia
COPY flag.txt ./flag.txt

RUN chown root:root indonesia flag.txt \
	&& chmod 555 indonesia \
	&& chmod 444 flag.txt

USER ctf
EXPOSE 1337

CMD ["socat", "-T", "120", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/indonesia,stderr"]
