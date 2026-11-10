# Claude Watch 完整重置、打包与安装流程

本流程记录项目当前的协作方式：协作者核对范围，用户自行执行统一入口 `monitor/reinstall.sh`（内部是 Rust 引擎的 `reinstall` 子命令）完成 Claude Watch 的卸载、完整重置、打包和安装，之后再核验实际运行情况。脚本适用于此项目当前的 macOS 26 或更新系统、Apple Silicon `arm64`、Rust 候选后台；最低支持版本统一取自 `monitor/macos-minimum.txt`。每次使用前核对脚本和用户指定的目标版本。

流程是操作方法，不是将来操作的授权。每次按用户当次明确授权确定是否卸载、删除 Watch 数据和安装；一句明确要求“完整重置并卸载”的指令可以覆盖其中所述的清理范围，无需再逐项重复确认。提交、推送、发布以及修改 TAG 配置不包含在本流程中。

## 1. 清理前核对

1. 确认当前安装的应用路径、Bundle ID `io.local.watchpanel`、版本、构建号、后台类型和实际进程；确认需要安装的新版本号。核对目标不是符号链接，且只属于 Claude Watch。
2. 检查 Watch 进程、主后台和更新任务，以及账号切换、环境初始化、服务设置、更新或后台安装等是否有正在进行或尚待恢复的事务。若有，暂停清理，先查明状态；不要强杀进程或删除锁和事务文件来绕过它。
3. 完整重置会删除 Watch 自身保存的账号快照、配置、历史、日志和缓存，需要在新版本中重新设置。Claude 自身登录和数据、TAG 配置，以及独立原版保镖和时区守护不属于清理范围。若要借旧日志排查问题，先在清理前检查并记录必要的脱敏结论；不要擅自备份或导出数据。

## 2. 卸载与完整重置

按当前实际安装版本选择对应的卸载方式，先预览或核对其作用范围。当前 Rust 候选版可使用已安装应用的 `watch-engine app-uninstall` 预览，再在已授权后加 `--apply` 执行。它会停止自有主后台、移走应用和主后台任务并重置本工具的辅助功能授权；它本身保留 Watch 数据，不能代替完整重置。旧稳定版应核对对应版本的卸载器，不强行套用 Rust 命令。

在确认服务已停止、路径身份和归属正确之后，清理 Watch 自身的以下数据和残留；不存在的项跳过：

- `~/Library/Application Support/ClaudeWatch`：包括 Watch 的账号快照、设置、日志、状态和运行组件。
- `~/Library/Preferences/io.local.watchpanel.plist`，以及实际存在且已核实属于该应用的缓存、日志、WebKit、HTTP 存储、容器或保存状态。
- `~/Library/LaunchAgents/io.local.claudewatch.agent.plist`、`io.local.claudewatch.update.plist` 及其对应的 Watch 用户任务；先核验任务定义，停止并清理属于本工具的项。
- 本次卸载创建的 `~/.Trash/ClaudeWatch-removed-<标识>`：核对其来源和内容后仅清理该目录，不清空整个废纸篓。

检查 Watch 自己的系统时区守护和辅助组件：`system/io.local.claudewatch.timezone`、`/Library/LaunchDaemons/io.local.claudewatch.timezone.plist` 和 `/Library/Application Support/ClaudeWatch`。如果存在这些残留，确认管理员脚本的身份、权限及 `uninstall` 分支确实只处理本工具后，使用它清理；如需管理员密码，由用户在终端执行：

```bash
sudo '/Library/Application Support/ClaudeWatch/claude-watch-admin.sh' uninstall
```

如果仍有残留但脚本缺失，或脚本身份不匹配、残留无法解释，先报告并核实，不扩大删除范围。保留 Claude 自身登录和配置、TAG 配置、`local.claude-bodyguard`、`local.tz-watchdog` 和 `~/.claude-switcher` 等独立原版组件。不要清空整个废纸篓，也不要顺带删除项目中的其他构建产物。

## 3. 清理结果核验

实际检查安装应用、Watch 用户数据和偏好设置、主后台和更新任务、Watch 自有系统时区任务及辅助组件是否已按范围清除，检查是否仍有本工具进程。分别说明 Claude 登录和 TAG 等保留对象的检查结果；遇到权限不足或不确定的项，列明未完成部分。清理未完成时先处理阻塞，再进入打包环节。

## 4. 用户运行统一脚本

先正常退出 Claude。将下例的版本号和 build 号改为用户当次明确指定的值；`3.0.0 314` 仅是示例，不会自动递增。只查看计划而不修改系统时运行：

```bash
bash /Users/anyun/Desktop/bash/monitor/reinstall.sh 3.0.0 314 --dry-run
```

确认范围后，去掉 `--dry-run` 执行完整流程：

```bash
bash /Users/anyun/Desktop/bash/monitor/reinstall.sh 3.0.0 314
```

脚本会先展示现有版本与目标，要求输入 `y` 确认，然后依次卸载、清理和核验、打包、校验、安装并打开新版。系统辅助组件存在时可能需要用户输入管理员密码。相同路径的旧构建产物不会被覆盖，编译仍可复用项目的缓存。

统一入口的前置 Rust 构建与打包阶段共用 `tools/build-rust-components.sh`，构建相同的 engine、nono launcher 和 gateway broker，使用相同的 target、SDK、linker 与依赖功能组合。前置内部使用 `--build-only`，不暂存或运行组件；后续打包仍检查 Cargo 增量状态。不要另外先执行 Cargo 构建或 `monitor/build.sh`，也不能仅凭构建目录相同就宣称没有重复编译。

脚本只支持已核对的 Rust 候选版；发现未完成事务、正在运行的更新或其他打包任务、未知辅助组件，或应用缺失但 Watch 仍有残留时会停止。流程先卸载再打包，如果打包失败旧应用已经卸载。遇到失败先保留输出并核对当前状态，不盲目重试。

打包脚本在支持时使用 `diskutil image`，其他系统回退到 `hdiutil`；出现警告时保留原始输出并检查具体原因。DMG 内的 `安装或更新后台.command` 是保留现有 Watch 数据的普通安装入口，不能代替完整重置。

### 系统网络扩展的正式构建条件

以下条件仅适用于明确选择的历史 `network-extension` 后端。当前默认是 Rust＋nono/Seatbelt，使用免费的本机 ad-hoc 签名，无需开发者会员或 Developer ID 证书；不能把本节作为默认重装流程的前置要求。

默认 `monitor/build.sh` 仍生成临时签名的开发产物，适合编译与隔离验证，不能视为系统网络接管可用。正式构建支持以下环境变量；重装入口会向构建进程继承这些变量，但设置变量本身不授权安装：

| 变量 | 用途 |
|---|---|
| `CW_SIGNING_IDENTITY` | 本机可用的 Developer ID Application 签名身份；默认 `-` 表示开发签名。 |
| `CW_HOST_PROVISION_PROFILE` | `io.local.watchpanel` 的有效 Developer ID profile，须含 Network Extension 与 System Extension 安装能力。 |
| `CW_EXTENSION_PROVISION_PROFILE` | `io.local.watchpanel.network-extension` 的有效 Developer ID profile，须含 `app-proxy-provider-systemextension`。 |
| `CW_REQUIRE_ENTITLED_NETWORK_EXTENSION` | 设为 `1` 时要求正式权限构建；签名身份缺失或为 `-` 时立即失败，不能降级为开发产物。默认 `0`，只接受 `0/1`。 |

兼容变量名 `CW_CODESIGN_IDENTITY`、`CW_HOST_PROFILE`、`CW_EXTENSION_PROFILE`，以及旧版本的 `CW_SIGN_IDENTITY`、`CW_APP_PROVISIONING_PROFILE`、`CW_EXTENSION_PROVISIONING_PROFILE`；同一用途的变量同时设置且值不一致时停止构建。Entitlement 模板统一位于 `monitor/Signing/`，构建时生成带 Team ID 的签名输入。

构建时检查两个 profile 的应用标识、有效期、同一 Team ID 与所需 entitlement，签名内部组件、扩展与宿主，再核验签名。宿主显式配置当前用户的控制目录，Rust 不从 UI 状态缓存认定接管生效。能力和 profile 的平台要求参见 [Apple 的 Network Extensions entitlement 文档](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)。

这条正式签名构建路径不自动执行公证或系统批准，也不证明扩展已运行。实际交付仍须具备相应证书、profile、必要公证和用户批准，并核验扩展新鲜心跳、匹配命令的执行回执及真实应用流量。本轮只完成源码与静态构建入口核对，未执行正式签名、安装或激活。

## 5. 安装后核验

完整重置后首次打开新版，先进入初始化向导。Claude Watch 保镖和时区守护起初关闭；向导先核对组件、代理、环境、权限、DNS 和 WebRTC，再展示自有守护启用预览，由用户确认并按 macOS 提示授权。向导中的检查全部真实通过且联合复核有效后，才能进入主界面；未知、超时、权限不足和失败均不能跳过。

初始化结果与主界面共用同一组 Store 和后台回执。首次完成后，关闭并重新打开应用或重启电脑均保留开启选择，不必重复手动启用；完整重置会清除初始化完成记录。失败时在向导内重试或保存脱敏检查记录；进入主界面不替代 Claude 的独立启动保护校验。

协作者核对已安装应用的 Bundle ID、版本、构建号、架构、后台类型和签名，检查主后台任务及实际运行状态。用户打开新版后，再按本次目标检查界面、数据刷新和相关功能；需要验证启动保护、DNS 或 WebRTC 时分别检查对应实际行为。打包成功、安装成功和真实运行验收分别报告，不因安装器返回成功就认定后台健康或所有保护功能通过。不要为了核验擅自启动 Claude 或修改 TAG、账号及保护配置。

后台先发布已核验的原生进程观测，再完成可能较慢的首次应用发现和网络采样。初始化观测必须显示未就绪、网络未知且不授予启动许可；仍须通过原有生产者身份、固定后台关系与新鲜度校验。安装器的 15 秒启动等待没有放宽，进程已启动与网络保护已生效仍是两种不同证据。

### Seatbelt 网关接入重装（免费本机签名）

统一重装入口会在删除任何 Watch 数据前预演系统网关，确认首次安装或同用户、同最终引擎路径的已有安装；不认识的服务、文件或未恢复事务直接阻止继续。确认提示包含管理员网关安装/更新。仍使用本机 ad-hoc 签名，无需付费开发者签名；不修改 VPN/TAG。

打包期间保留旧网关端点。新运行组件最终落位后，才绑定新引擎和 broker 身份并请求管理员授权。随后必须由最终路径的用户引擎实际领取并验证 IPv4/IPv6 监听句柄，才启动后台。管理员取消、端口冲突或验证失败都不能被显示为安装正常。

安装失败回滚本次网关变更；运行组件已提交之后的 root 事务清理失败会明确报告 `gateway_cleanup_pending`，保留新版本和恢复记录，不再单独回退应用造成身份不一致。网关管理命令用 root 文件锁串行，原管理员操作仍运行时拒绝并发回滚。完整实机安装、管理员授权及真实客户端保护仍需用户另外验收；隔离测试不代替这些证据。

### 自动保存本次重装日志

统一命令不变，组件仍只按既有入口编译一次。构建与安装的阶段结果自动保存在：

`~/Library/Logs/ClaudeWatchInstaller/reinstall-时间-标识/run.json`

该目录不在 Watch 重置删除范围中。`run.json` 保存阶段、目标版本/构建号（格式校验后）、真实退出码、耗时和日志可用性；`build.log`、`install.log` 是终端输出的有界过滤副本。终端仍实时显示原输出，确认和密码输入继续使用原终端，输入本身不记录。编译失败时保留失败结果，不继续安装，不二次编译；日志写入失败不会替换原操作退出码。

每个文本日志最多512KiB及一份轮转；最多保留5个已知运行目录，当前未完成运行不自动删除。达到限额或遇到未知文件会明确提示日志不可用，原安装流程继续。过滤会移除常见凭据行、URL路径/查询、邮箱和用户主目录，但不能保证任意终端文本绝对不含秘密；对外诊断只选择`run.json`中的安全字段，不自动导出原始文本副本。
