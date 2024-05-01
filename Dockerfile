FROM ubuntu:latest

RUN apt update && apt -y upgrade

RUN apt install -y git \
                   build-essential \
                   gcc \
                   g++ \
                   cmake \
                   autoconf \
                   clang \
                   doxygen \
                   graphviz \
                   libboost-all-dev\
                   libtool \
                   wget \
                   pkg-config \

# docker build -t pdm-linux-env .
# docker run -it --name pdm-linux-container pdm-linux-env
# docker start -ai pdm-linux-container
