# bpf-disruptor
Basic eBPF examples in Golang using [libbpfgo](https://github.com/aquasecurity/tree/main/libbpfgo). 

## Install Go 

See [the Go documentation](https://golang.org/doc/install)

## Install packages

```sh
sudo apt-get update
sudo apt-get install libbpf-dev make clang llvm libelf-dev
```

## Building and running hello

```sh
make all
sudo ./hello
```

This builds two things:
* dist/injection.bpf.o - an object file for the eBPF program
* injection - a Go executable

The Go executable reads in the object file at runtime. Take a look at the .o file with readelf if you want to see the sections defined in it.

## Docker

To avoid compatibility issues, you can use the `Dockerfile` provided in this repository.

Build it by your own:

```bash
docker build -t build-injection .
```

And the run it from the project directory to compile the program:

```bash
docker run --rm -v $(pwd)/:/app/:z build-injection
```

## Notes 

I'm using Ubuntu 23.04, kernel 5.15, go 1.19

This approach installs the libbpf-dev package. Another alternative (which is what [Tracee](https://github.com/aquasecurity/tracee) does) is to install the [libbpf source](https://github.com/libbpf/libbpf) as a git submodule, build it from source and install it to the expected location (e.g. `/usr/lib/x86_64-linux-gnu/libbpf.a` on an Intel x86 processor).
