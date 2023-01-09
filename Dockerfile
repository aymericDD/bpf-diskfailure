FROM ubuntu:lunar 

# Define variables.
ARG GOVERSION=1.19.4
ARG ARCH=arm64

# Download development environment.
RUN apt-get update && \
    apt-get install -y \
        libbpf-dev \
	pahole \
        make \
        clang \
        llvm \
        libelf-dev

# Install Go specific version.
RUN apt-get install -y wget && \
    wget https://golang.org/dl/go${GOVERSION}.linux-${ARCH}.tar.gz && \
    tar -xf go${GOVERSION}.linux-${ARCH}.tar.gz && \
    mv go/ /usr/local/ && \
    ln -s /usr/local/go/bin/go /usr/local/bin/ && \
    rm -rf go${GOVERSION}.linux-${ARCH}.tar.gz

# Setup working directory.
RUN mkdir -p /app
WORKDIR /app

# Execute build command.
ENTRYPOINT ["/usr/bin/make", "all"]
