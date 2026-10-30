# Claude Watch 完整重置、打包与安装流程

本流程记录项目当前的协作方式：协作者核对范围，用户自行执行统一脚本完成 Claude Watch 的卸载、完整重置、打包和安装，之后再核验实际运行情况。脚本适用于此项目当前的 Apple Silicon `arm64`、Rust 候选后台；每次使用前核对脚本和用户指定的目标版本。

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
/usr/bin/python3 /Users/anyun/Desktop/bash/monitor/reinstall_clean.py 3.0.0 314 --dry-run
```

确认范围后，去掉 `--dry-run` 执行完整流程：

```bash
/usr/bin/python3 /Users/anyun/Desktop/bash/monitor/reinstall_clean.py 3.0.0 314
```

脚本会先展示现有版本与目标，要求输入 `重置并安装`，然后依次卸载、清理和核验、打包、校验、安装并打开新版。系统辅助组件存在时可能需要用户输入管理员密码。相同路径的旧构建产物不会被覆盖，编译仍可复用项目的缓存。

脚本只支持已核对的 Rust 候选版；发现未完成事务、正在运行的更新或其他打包任务、未知辅助组件，或应用缺失但 Watch 仍有残留时会停止。流程先卸载再打包，如果打包失败旧应用已经卸载。遇到失败先保留输出并核对当前状态，不盲目重试。

打包脚本在支持时使用 `diskutil image`，其他系统回退到 `hdiutil`；出现警告时保留原始输出并检查具体原因。DMG 内的 `安装或更新后台.command` 是保留现有 Watch 数据的普通安装入口，不能代替完整重置。

## 5. 安装后核验

完整重置后首次安装本次修改后的版本，Claude Watch 保镖和时区守护默认关闭，由用户分别手动开启；之后关闭并重新打开应用或重启电脑时，保留此前的开启或关闭选择。开启时区守护需要按系统提示完成管理员授权。

协作者核对已安装应用的 Bundle ID、版本、构建号、架构、后台类型和签名，检查主后台任务及实际运行状态。用户打开新版后，再按本次目标检查界面、数据刷新和相关功能；需要验证启动保护、DNS 或 WebRTC 时分别检查对应实际行为。打包成功、安装成功和真实运行验收分别报告，不因安装器返回成功就认定后台健康或所有保护功能通过。不要为了核验擅自启动 Claude 或修改 TAG、账号及保护配置。
