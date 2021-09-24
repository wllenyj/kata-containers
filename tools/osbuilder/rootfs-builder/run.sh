#!/bin/bash
export GOPATH=/home/wanglei01/opt/open/go/
#export AGENT_INIT=yes
#export AGENT_BIN=${GOPATH}/github.com/kata-containers/agent/kata-agent
export AGENT_SOURCE_BIN=/home/wanglei01/opt/work/kata/agent-rs/src/agent/target/x86_64-unknown-linux-musl/release/kata-agent
export EXTRA_PKGS="openssl openssl-devel bash coreutils net-tools iproute openssh-server nmap-ncat lsof initscripts vim-minimal perf strace ltrace trace-cmd setup yum"
export USE_DOCKER=true
export OS_VERSION=8
DEBUG=1 ./rootfs.sh centos $1

install -o root -g root -m 0440 ../../../src/agent/kata-agent.service ${1}/usr/lib/systemd/system/
install -o root -g root -m 0440 ../../../src/agent/kata-containers.target ${1}/usr/lib/systemd/system/


#cp -a rootfs-Centos_debug/lib/systemd/system/kata-* ./rootfs-Centos/lib/systemd/system/
#cp -a rootfs-Centos_debug/etc/ssh/* ./rootfs-Centos/etc/ssh/
#chpasswd -R /home/wanglei01/opt/open/go/src/github.com/kata-containers/osbuilder/rootfs-builder/rootfs-Centos < ./passwords.txt

#cp -a /etc/resolv.conf ./rootfs-Centos/etc/resolv.conf
