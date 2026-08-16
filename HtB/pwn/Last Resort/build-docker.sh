#!/bin/bash
docker build --tag=pwn_last_resort .
docker run -p 1337:1337 --rm --name=pwn_last_resort -it pwn_last_resort
