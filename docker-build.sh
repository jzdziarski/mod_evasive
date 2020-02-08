#!/bin/bash

docker build . -t mod_evasive || exit 1
docker run -t -d -p 1980:80 mod_evasive
./test/test.pl
docker ps -a | grep mod_evasive | awk -F "  +" '{print $7}' | xargs docker stop
