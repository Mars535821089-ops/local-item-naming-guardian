PYTHON ?= /usr/bin/python3
APP_EXEC = 系统维护-命名管家-核查新增项目并记录用途
.PHONY: build test install
build: launcher $(APP_EXEC)
launcher: launcher.c
	/usr/bin/clang -Wall -Wextra launcher.c -o launcher
$(APP_EXEC): Guardian.swift
	/usr/bin/swiftc Guardian.swift -o '$(APP_EXEC)' -framework Cocoa -framework CoreServices
test: build
	$(PYTHON) -m unittest -v
install: test
	$(PYTHON) install.py
