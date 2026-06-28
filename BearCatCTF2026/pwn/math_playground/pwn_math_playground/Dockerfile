FROM debian:bookworm-20251208-slim

RUN apt-get update && apt-get install -y build-essential gcc gcc-multilib libc6 gdb && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN useradd -d /home/ctf/ -m -s /bin/bash ctf -p '$6$ELimC.kWCpTCq80.$46kdym4ZQZJg1.ZWge7ufcd6UsXrI8DC/OkXGcgNGq3xr0ZGEs5YDir9Yyl23KZgVDO4Ut2YWXdZkYc.HAh3H.'

WORKDIR /home/ctf

COPY math_playground .
COPY flag.txt .
COPY ynetd.c .
COPY Makefile .

RUN chown -R root:root .
RUN make
RUN chmod 755 . math_playground ynetd
RUN chmod 644 flag.txt

EXPOSE 5000
CMD ./ynetd -p 5000 ./math_playground
#CMD ./ynetd -t 60 -lt 10 -lm 33554432 -p 5000 -u ctf 'linux32 -R ./math_playground'
