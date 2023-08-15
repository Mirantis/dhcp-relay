# Makefile variables.
PROJECT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Project-specific variables.
IMAGE_DEFAULT_NAME := dhcp-relay
IMAGE_DISPLAY_NAME := "DHCPv4 Relay Agent"
IMAGE_DESCRIPTION := "DHCPv4 Relay Agent written in Golang"

# Name of output binary.
BIN_NAME := $(or $(BIN_NAME),dhcp-relay)

# Path to project root directory.
PROJECT_DIR := $(abspath $(or $(PROJECT_DIR),./))

# Artifacts output directory.
ARTIFACTS_DIR := $(abspath $(or $(ARTIFACTS_DIR), $(addprefix $(PROJECT_DIR),/BUILD)))

include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.common))
include $(abspath $(addprefix $(PROJECT_DIR),/Makefile.docker))

all: check build

# Run all checks.
.PHONY: check
check: clean tidy verify lint test check-git-clean
