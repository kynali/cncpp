FROM ubuntu:20.04

LABEL maintainer="<https://github.com/aligungr/UERANSIM>" \
    description="UERANSIM-5G-AKA from Free5gc" \
    version="v3.1.0"

RUN apt update; \
    apt install -y ca-certificates
# source of Tsinghua University
COPY sources.list /etc/apt
RUN apt update

# Install debug tools
RUN apt install -y net-tools iputils-ping curl termshark 
# Install dependencies
# make, gcc/g++, cmake packages are only required for building UERANSIM. 
# However, libsctp-dev, lksctp-tools, iproute2 packages are also required at runtime.
RUN apt install -y nano vim sudo make gcc g++ libsctp-dev lksctp-tools iproute2 wget git iperf3

# new user: ubuntu
RUN useradd --create-home --shell /bin/bash ubuntu; \
    adduser ubuntu sudo; \
    echo 'ubuntu:ue' | chpasswd
USER ubuntu
WORKDIR /home/ubuntu

COPY cmake-3.22.0-linux-x86_64.tar.gz /home/ubuntu
# If do not trust it, please get official package by the command below.
# RUN wget https://cmake.org/files/v3.22/cmake-3.22.0-linux-x86_64.tar.gz
RUN tar -xzvf cmake-3.22.0-linux-x86_64.tar.gz

# Get UERANSIM
RUN git clone -b v3.1.0 https://gitee.com/wlwdhr/github_ueransim.git

# make
COPY makefile ./UERANSIM
RUN cd UERANSIM; \
    make -j`proc`

RUN rm cmake-3.22.0-linux-x86_64.tar.gz; \
    rm -rf cmake-3.22.0-linux-x86_64