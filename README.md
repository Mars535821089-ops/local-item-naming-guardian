# 本机项目命名管家

macOS 本地新增项目观察器与规范化注册工具。独立于 GPT、Claude 和其他 AI 客户端，也能观察普通软件安装、更新和首次运行产生的项目。

**当前版本支持基于证据规则的自动规范化和名称回退恢复，同时保留全系统变化观察。** 它不会修改第三方应用签名、权限数据库、启动开关，不自动删除项目，也不会调用后台 AI CLI。已核实的用户级 LaunchAgent 自动生成用途名称包装器；每次巡检检查并恢复同一身份下的名称回退。源码、真实目标或业务配置变化后停止自动操作。不会根据模糊名字猜用途。

## 功能

- 原生菜单栏入口：查看项目用途、累计变更、覆盖范围，手动核查或退出。
- FSEvents 观察应用和启动服务等目录；事件后核查，连续事件至少间隔约一分钟；每五分钟补查，登录后自动运行。
- 应用目录及 Spotlight 已索引应用、内嵌启动服务、XPC/应用扩展、系统扩展、传统 LaunchAgent/Daemon、音频 HAL、偏好面板、快捷服务。
- 可读取的后台注册库、隐私权限元数据、防火墙记录；通知、网络扩展及控制中心部分存储仅跟踪指纹变化。
- 新增、变化和不可见项目分类。外置卷未挂载、读取权限不足都不作为删除证据。
- 无网络调用、遥测、模型供应商依赖；不保存启动参数内容或环境变量，只计算配置摘要。报告包含本机应用路径，存于用户私有目录，不应公开。
- 独立注册入口要求 `类别-项目-具体用途`、用途说明、存在的项目目录和可执行目标。生成具名应用包装器和用户启动项，拒绝覆盖既有注册。

## 边界

- 第三方软件没有经过注册入口时不能被强制要求填写用途；检测到不代表允许改名。
- 文件事件不等于创建者身份证明。只从应用包内嵌关系等明确证据归属，不因时间接近就归因。
- 不能自动推断所有陌生程序的真实业务用途；没有证据的原样保留并记录。
- 后台程序可能需要用户手动授予完全磁盘访问，才可读取更多系统元数据；即使授予也不保证所有受保护隐私库可读。不绕过系统保护。
- BTM 解析目前识别本机验证的 v18 格式；其他格式报告缺口。
- 未索引、非标准路径、离线外置卷、其他用户私有目录不能保证全部发现。不会递归扫描个人文件或整块外置硬盘。
- 自动规则绑定精确源码摘要、目标程序摘要和业务配置摘要。只修改用户所属启动配置的 `Program`、`ProgramArguments[0]`、`AssociatedBundleIdentifiers`；参数、环境、启用状态与其他字段保持。文件的 ACL、模式和扩展属性保留。
- 原始目标来源只登记一次。事务日志不保存业务参数或环境值，重复执行不会将包装器写成自己的目标。提交时原子领取原配置并复验，再通过 Darwin 独占重命名提交；如果更新器已创建新配置，绝不覆盖，原件留在启动项目录下私有 `.naming-recovery/`。提交期间崩溃可能短暂留下缺失的 plist；下次巡检只在目标路径仍缺失、私有恢复记录与原件哈希一致时独占恢复原件，再重新核验。路径已被更新器创建时绝不覆盖。
- 不停止、重启或新启动业务服务。仅对原本已加载的任务尝试不带启用/强制参数的重复登记以刷新显示；已用独立空闲服务验证不会重新执行结束的任务。禁用和未加载任务只修改磁盘配置，其系统显示可能要等下次正常注册或登录。实际显示未匹配时最多每五分钟重试登记。
- 系统级服务、签名应用内嵌服务、特殊安全语义配置、未登记用途和证据变化的项目不会自动强改。
- 规范注册入口能检查结构和路径，不能证明人填写的用途一定真实；也不能保证 macOS 每个设置页面立即采用包装器名称。
- Swift 程序退出时不主动终止已在运行的只读核查；最长核查超时设为 180 秒。

## 构建与安装

需要 macOS、Xcode Command Line Tools 的 Swift/C 编译器及 `/usr/bin/python3`（Python 3.9+）。不安装第三方 Python 包。构建默认输出至本机外置盘 `/Volumes/Mars-私人服务器/内置盘写入统一管理/01-编译与构建/本机项目命名管家/`，缺盘失败；可明确指定 `BUILD_DIR`，仍需默认外盘已挂载。源码和私有状态留在内置。

```sh
make test
make install
# 已安装时仅更新 Python 执行逻辑，不重新签名主应用：
make update-runtime
```

安装位置：

- `~/Applications/系统维护-命名管家-核查新增项目并记录用途.app`
- `~/Library/LaunchAgents/com.mars.item-naming-guardian.plist`
- `~/Library/Application Support/Mars Item Guardian/`：程序、清单、变更记录、用途规则与 HTML 看板。

安装器拒绝覆盖现有应用或启动项。`make update-runtime` 在巡检锁保护下更新 Python 代码，不重新签名主应用，以免影响已授予的访问权限。无管理员权限要求；完全磁盘访问由使用者自行决定。

## 规范化登记（适用于任意工具或人工）

准备 JSON 文件，使用真实绝对路径；不要填写凭据：

```json
{
  "name": "开发维护-示例项目-每日整理项目构建日志",
  "purpose": "登录后运行项目自身提供的日志整理入口，保留业务文件",
  "project": "/absolute/path/to/project",
  "executable": "/absolute/path/to/project/start-maintenance"
}
```

```sh
/usr/bin/python3 "$HOME/Library/Application Support/Mars Item Guardian/guardian.py" register manifest.json
# 检查计划后实际登记：
/usr/bin/python3 "$HOME/Library/Application Support/Mars Item Guardian/guardian.py" register manifest.json --apply
```

登记不会立即执行目标，下次登录生效。若不希望下次登录运行，不要使用 `--apply`。仅支持无参数入口；需要参数的项目自己提供启动器，凭据应由项目从 Keychain 读取。直接注册 `claude` / `codex` CLI 被拒绝，但本工具不能审计任意脚本内部行为。

退出/停用命名管家：菜单“退出本次运行”仅停到下一次登录。永久停用可执行：

```sh
launchctl bootout "gui/$(id -u)/com.mars.item-naming-guardian"
```

然后将上述专属启动 plist 移到废纸篓。需要完全卸载时再移除本应用和专属数据目录；不要删除它观察到的其他项目。注册入口生成的每个任务都有 `registration.json`，记录自己的精确标签、路径和卸载说明。

## 测试

`make test` 当前包含 43 项测试，覆盖身份变化保护、自动恢复命名、离线来源、未知任务保留、并发更新器独占提交、真实子进程中断后的事务恢复、并发规则登记、畸形声明隔离、禁用和运行状态变化保护、扩展属性保留、HTML 转义、原始目标与自引用保护。自动测试不加载业务任务、不改系统权限；额外本机验收使用独立临时服务验证后台自动执行和空闲任务不重复执行，验收后移除测试服务。

仓库仅发布源码、构建脚本、测试和说明。本机实际用途规则、程序清单、权限记录、变更记录和验收快照不纳入 Git。


## 自动规范既有启动项

确认来源和用途后登记一次，随后后台巡检自动执行；不会立刻运行目标程序：

```sh
/usr/bin/python3 "$HOME/Library/Application Support/Mars Item Guardian/guardian.py" approve \
  "$HOME/Library/LaunchAgents/local.example.worker.plist" \
  '开发维护-示例项目-每日整理项目构建日志' \
  --source /absolute/path/to/project/worker.py
```

登记记录保存于私有 `normalization/rules.json`。证据变化会保护跳过，不自动扩大原有批准。`automatic-naming.json` 区分“启动配置已规范”和“系统后台显示已核验”，不能以文件修改代替设置显示验收。

恢复指定服务的原入口字段并停用该自动规则（保留后续无关字段变化）：

```sh
/usr/bin/python3 "$HOME/Library/Application Support/Mars Item Guardian/guardian.py" restore local.example.worker
```

任何本机工具也可提交完整用途声明到私有 `normalization/requests/任意唯一名称.json`，文件权限须为 `0600`：

```json
{
  "plist": "/absolute/home/Library/LaunchAgents/local.example.worker.plist",
  "name": "开发维护-示例项目-每日整理项目构建日志",
  "purpose": "定时处理该项目可重新生成的构建日志，不处理业务数据",
  "sources": ["/absolute/path/to/project/worker.py"]
}
```

下一次后台巡检消费声明，登记证据后自动规范；结果在 `normalization/request-results/`。已经有规则的同标签不会被新声明覆盖。这个本机入口不依赖某个 AI，也不会拦截第三方安装器。声明真实性仍由提交者负责，系统不会凭名称猜用途。

看板当前待处理项目与累计变更历史分开：`待核查.json` 是当前问题，`变更历史.json` 保留历史事件。旧版菜单栏仍可能将当前条目称为“累计变更”；看板和 JSON 的含义以上述说明为准。无需为该文字重签已经获准访问的应用。
