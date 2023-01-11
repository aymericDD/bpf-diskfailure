ARCH=$(shell uname -m)

TARGET := injection
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a

.PHONY: all
all: $(TARGET) $(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET) 

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-D__TARGET_ARCH_arm64 \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf \
		-g \
		-o $@ $<

.PHONY: clean
clean:
	go clean
	
