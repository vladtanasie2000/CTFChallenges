#!/bin/sh
docker build --tag=pwn_funkynator_mp .
docker run -it -p 1337:1337 --rm --name=pwn_funkynator_mp pwn_funkynator_mp
