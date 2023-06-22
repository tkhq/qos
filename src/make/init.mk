ifeq ("$(wildcard ./src/toolchain)","")
	gsu := $(shell git submodule update --init --recursive)
endif

TARGET := aws
