PYTHON ?= /usr/bin/python3
BUILD_DIR ?= /Volumes/Mars-私人服务器/内置盘写入统一管理/01-编译与构建/本机项目命名管家
APP_EXEC = 系统维护-命名管家-核查新增项目并记录用途
.PHONY: build test install update-runtime check-build-dir
check-build-dir:
	@test -d '/Volumes/Mars-私人服务器' && /sbin/mount | /usr/bin/grep -q ' on /Volumes/Mars-私人服务器 (' || { echo 'Required external build volume is not mounted'; exit 1; }
	@mkdir -p '$(BUILD_DIR)'
build: check-build-dir
	/usr/bin/clang -Wall -Wextra launcher.c -o '$(BUILD_DIR)/launcher'
	/usr/bin/swiftc Guardian.swift -o '$(BUILD_DIR)/$(APP_EXEC)' -framework Cocoa -framework CoreServices -module-cache-path '$(BUILD_DIR)/module-cache'
test: build
	GUARDIAN_LAUNCHER='$(BUILD_DIR)/launcher' PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -q
install: test
	$(PYTHON) install.py --build-dir '$(BUILD_DIR)'
update-runtime:
	$(PYTHON) install.py --update-runtime
