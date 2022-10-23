FROM ubuntu:20.04

LABEL maintainer="kynali <https://github.com/kynali>" \
    description="CNCPP-5G-AKA" \
    version="0.2.0 Debug 5G-AKA"

RUN apt update; \
    apt install -y ca-certificates
# source of Tsinghua University
COPY sources.list /etc/apt
RUN apt update

# Install debug tools
RUN apt install -y net-tools iputils-ping curl
# Install dependencies
RUN apt install -y sudo git; \
    apt update; \
    DEBIAN_FRONTEND=noninteractive apt install -y golang-go

# new user: ubuntu
RUN useradd --create-home --shell /bin/bash ubuntu; \
    adduser ubuntu sudo; \
    echo 'ubuntu:ue' | chpasswd
USER ubuntu
WORKDIR /home/ubuntu

# Get CNCPP-bcaka
RUN git clone https://gitee.com/liu-zhao234568/cn_spk.git

# set go env and go build
RUN export GO111MODULE=on; \
    export GOPROXY=https://goproxy.cn,direct; \
    cd cn_spk; \
    go build