FROM ubuntu:22.04

RUN apt update
RUN apt install build-essential gcc-multilib socat -y
RUN mkdir /chal

WORKDIR /chal

COPY ./chal.c .
COPY ./flag.txt .

RUN gcc chal.c -o chal -fno-stack-protector -no-pie -z execstack -m32

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:\"./chal\""]