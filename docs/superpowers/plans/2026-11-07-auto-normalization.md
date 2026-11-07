# 自动规范化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. 用户已要求直接实现；沿用已授权范围连续执行。

**Goal:** 已核实启动项目自动改名并恢复名称回退。
**Architecture:** 私有规则 + 独立 normalizer.py + 现有巡检接入。每次写入只改入口元数据；不重启业务程序。签名软件、未知用途和根级文件保留。
**Tech Stack:** Python 3.9 标准库、现有 C 用途包装器、launchctl、codesign。
**Spec:** docs/superpowers/specs/2026-11-07-auto-normalization-design.md

## Global Constraints
- 不删除项目、不切换开关、不重启业务、不绕过权限、不执行 AI CLI。
- 源码/Git与私有状态内置；构建与可配置缓存外置，缺盘失败。
- 不公开本机清单、参数、凭据或私有规则。

## Review Focus
- 二次运行不得覆写真实目标为包装器自身；重复执行无变化。
- 安装器原子替换配置时，不覆盖未知更新。
- 外置卷不可见、源码或身份变化时跳过。
- 未加载/禁用服务不得因显示刷新而启动。
- 报告必须区分已规范配置与系统注册实际显示。

### Task 1: 安全规则、包装器与事务
Files: normalizer.py, test_normalizer.py
- [x] 写身份匹配、重复执行、回退恢复、源码变化、链接/越界、外盘离线、并发替换、参数和开关保持、真实目标保护的失败测试。
- [x] 实现 enroll_rule / normalize / restore；只改 Program、ProgramArguments[0]、AssociatedBundleIdentifiers。
- [x] 测试通过；实现明确的停用和事务恢复命令。

### Task 2: 巡检与待办
Files: guardian.py, install.py, Makefile, test_guardian.py
- [x] 测试先验证巡检会触发执行且已处理项不再成为当前待办。
- [x] 巡检中使用规则执行，重新采集被修改服务并记录实际显示验证。
- [x] 规范入口生成同一自动恢复规则；旧规则导入保留目标来源。
- [x] 安装支持仅更新工作代码，主应用不重签；构建默认外置。

### Task 3: 本机验收与发布
Files: README.md, docs；本机私有运行状态
- [x] 独立审查、完整测试；只发布通用源码。
- [x] 当前已核实本地服务登记证据并由后台自动执行。
- [x] 对专用测试服务制造同身份名称回退，验证巡检自动恢复、业务 PID 不变、开关不变。
- [x] 复核实际后台显示；记录未处理根服务原因。
- [x] 合并、推送并核对远端提交。
