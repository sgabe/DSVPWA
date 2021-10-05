BUILD_VER := "0.0.1"
BUILD_REV := $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell git log --pretty=format:%ct -1)

all:
	docker build \
		--build-arg BUILD_VER=$(BUILD_VER) \
		--build-arg BUILD_REV=$(BUILD_REV) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--no-cache -t sgabe/dsvpwa:$(BUILD_VER) .
