# CXL P2P DMA Test Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS =

# CUDA paths (optional, for extended tests)
CUDA_PATH ?= /usr/local/cuda
CUDA_INC = -I$(CUDA_PATH)/include
CUDA_LIB = -L$(CUDA_PATH)/lib64

# Targets
TARGETS = cxl_p2p_test

.PHONY: all clean help

all: $(TARGETS)

cxl_p2p_test: cxl_p2p_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $@"

# Extended test with CUDA support
cxl_p2p_test_cuda: cxl_p2p_test.c
	$(CC) $(CFLAGS) $(CUDA_INC) -o $@ $< $(CUDA_LIB) -lcuda -lnvidia-ml $(LDFLAGS)
	@echo "Built: $@ (with CUDA support)"

clean:
	rm -f $(TARGETS) cxl_p2p_test_cuda

help:
	@echo "CXL P2P DMA Test"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build basic test"
	@echo "  cxl_p2p_test     - Build CXL P2P test"
	@echo "  cxl_p2p_test_cuda- Build with CUDA support"
	@echo "  clean            - Remove built files"
	@echo ""
	@echo "Usage:"
	@echo "  ./cxl_p2p_test [buffer_size_bytes]"
	@echo ""
	@echo "Examples:"
	@echo "  ./cxl_p2p_test              # Default 4MB buffer"
	@echo "  ./cxl_p2p_test 16777216     # 16MB buffer"
	@echo ""
	@echo "Requirements:"
	@echo "  - NVIDIA driver loaded"
	@echo "  - Access to /dev/nvidiactl"
	@echo "  - For real CXL: CXL-capable hardware"
