#!/bin/sh

docker build --tag=khp_protocol .

docker run -it \
    --rm \
    --name khp_protocol \
    -p 1337:1337 \
    --pid=host \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    khp_protocol