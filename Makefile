PROJECT_NAME = rksync-ca
BASE_VERSION = 1.0.3
IS_RELEASE = false

ARCH=$(shell go env GOARCH)
MARCH=$(shell go env GOOS)-$(shell go env GOARCH)
RYSYNC_TAG ?= $(ARCH)-$(BASE_VERSION)
PKGNAME = github.com/rkcloudchain/$(PROJECT_NAME)

ifneq ($(IS_RELEASE), true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION = $(BASE_VERSION)-$(EXTRA_VERSION)
else
PROJECT_VERSION = $(BASE_VERSION)
endif

METADATA_VAR = Version=$(PROJECT_VERSION)
GO_SOURCE := $(shell find . -name '*.go')
GO_LDFLAGS = $(patsubst %,-X $(PKGNAME)/metadata.%,$(METADATA_VAR))
DOCKER_TAG = $(ARCH)-$(PROJECT_VERSION)
DOCKER_NS ?= cloudchain

docker: $(patsubst %,build/image/%, $(PROJECT_NAME))

release: bin/rksync-ca

bin/%: $(GO_SOURCE)
	@echo "Building ${@F}" in bin directory
	@mkdir -p bin && go build -o bin/${@F} -ldflags "$(GO_LDFLAGS)" $(PKGNAME) 
	@echo "Built bin/${@F}"

build/image/%: Makefile build/image/%/payload
	$(eval TARGET=${patsubst build/image/%, %, ${@}})
	$(eval DOCKER_NAME=$(DOCKER_NS)/$(TARGET))
	@echo "Building docker $(TARGET) image"
	@cat images/$(TARGET)/Dockerfile.in > $(@)/Dockerfile
	docker build -t $(DOCKER_NAME) $(@)
	docker tag $(DOCKER_NAME) $(DOCKER_NAME):$(DOCKER_TAG)
	@touch $@

build/image/rksync-ca/payload:
	mkdir -p $@
	$(eval TARGET=${patsubst build/image/%/payload, %, ${@}})
	@echo "Building $(TARGET) in ${@} directory"
	go build -o $(@)/$(TARGET) -ldflags "$(GO_LDFLAGS)" $(PKGNAME)
	@echo "Built ${@}"
	@touch $@