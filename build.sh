#!/bin/bash
# build
docker build -t docker.cnb.cool/lingjiancode/fail2ban-ebpf .
# push
docker push docker.cnb.cool/lingjiancode/fail2ban-ebpf 
