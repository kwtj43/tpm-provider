#
# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
#--------------------------------------------------------------------------------------------------
# G T A - D E V E L
#--------------------------------------------------------------------------------------------------
# This docker image is used for building tpmprovider as well as for gitlab pipelines.  It uses
# Fedora 29 so that the versions of tss2 will align with what is present on RHEL8.
#--------------------------------------------------------------------------------------------------
# B U I L D I N G
#--------------------------------------------------------------------------------------------------
# Create the image...
# > docker build --tag=gta-devel --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg no_proxy=$no_proxy .
#
# Create a container...
# > docker run -d --rm -v $(pwd):/docker_host -p 1443:1443 --name=gta-devel gta-devel tail -f /dev/null
#
# Attach to the container, configure git and 'make'
# > docker exec -it gta-devel /bin/bash
# > git config --global http.proxy $http_proxy
# > git config --global https.proxy $https_proxy
# > git config --global url."ssh://<gitlab>:<port>".insteadOf https://<gitlab>
# > git config --global user.name "user name"
# > git config --global user.email "email"
# > cd /docker_host/tpm-provider
# > make
#
#--------------------------------------------------------------------------------------------------
# T P M   S I M U L A T O R
#--------------------------------------------------------------------------------------------------
# Start an instance of gta-devel that runs systemd, tpm2-abrdm and the tpm simulator...
# > docker run -d --rm --privileged -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host -p 1443:1443 --name=gta-devel gta-devel /usr/sbin/init
# > /simulator/src/tpm_server -rm&
# > systemctl start tpm2-abrmd
#--------------------------------------------------------------------------------------------------
FROM fedora:29

ENV container docker
ENV BASH_ENV "/root/.bashrc"
ARG http_proxy
ARG https_proxy
ARG no_proxy

RUN yum -y update

# this is needed so that the docker can run systemd and host the tpm simulator process
RUN yum -y install systemd && yum clean all && \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;

#  Install Development tools (gcc 8.3.1, ldd v2.28) and go-trust-agent dependencies
RUN yum -y group install "Development Tools" 
RUN yum -y install makeself gdb vim-common wget openssl-devel sudo dmidecode redhat-lsb tboot compat-openssl10 tpm2-abrmd tpm2-tools tpm2-abrmd-devel

# install go...
ENV GOLANG_TAR=go1.14.6.linux-amd64.tar.gz
RUN cd /tmp \
    && wget https://golang.org/dl/$GOLANG_TAR \
    && tar -C /usr/local -xzf $GOLANG_TAR \
    && rm -rf $GOLANG_TAR

# build the tpm simulator
RUN wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz \
    && mkdir simulator \
    && cd simulator \
    && tar -xavf ../ibmtpm1332.tar.gz \
    && cd src \
    && make

# update tpm2-abrmd.service to use the simulator (add --tcti=mssim parameter)
RUN sed -i 's|ExecStart=/usr/sbin/tpm2-abrmd|ExecStart=/usr/sbin/tpm2-abrmd --tcti=mssim|g' /usr/lib/systemd/system/tpm2-abrmd.service

# update paths, env, proxy, etc.
RUN echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
RUN echo "export http_proxy=$http_proxy" >> ~/.bashrc
RUN echo "export https_proxy=$https_proxy" >> ~/.bashrc
RUN echo "export no_proxy=$no_proxy" >> ~/.bashrc
