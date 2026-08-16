FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97 
RUN apt update --fix-missing && \
 apt install -y socat && \
 rm -rf /var/lib/apt/lists/*
# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf
ADD challenge/last_resort /home/ctf/
ADD challenge/flag.txt /home/ctf/
RUN chmod 444 /home/ctf/flag.txt
RUN chmod 775 /home/ctf/last_resort
USER ctf
WORKDIR /home/ctf
EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./last_resort"]
