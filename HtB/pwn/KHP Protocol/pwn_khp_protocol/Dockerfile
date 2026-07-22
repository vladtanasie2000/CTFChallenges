FROM ubuntu:22.04
EXPOSE 1337
RUN groupadd ctf && useradd -m -g ctf ctf
COPY challenge/ /home/ctf/
RUN chown ctf:ctf /home/ctf/users.keys

WORKDIR /home/ctf
USER ctf
CMD ["./khp_server", "-p", "1337"]
