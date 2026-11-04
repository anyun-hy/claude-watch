# Claude Watch

macOS 上的 Claude 受控启动、账号 A/B 切换与环境保护工具，同时观察 Claude、ChatGPT / Codex 的进程和代理连接。

当前源码以 Git `main` 提交为准；**应用版本与构建号由构建时显式指定**，仓库不代表当前已安装版本。发行目标为 **Apple Silicon（arm64）**，部署最低版本以 `monitor/macos-minimum.txt` 为准。

运行组件采用 Rust `watch-engine`，界面为 SwiftUI。已登记功能缺陷完成对应源码修复与隔离回归，但**尚未完成同一提交上的完整构建、实际安装与持续运行验收**。源码状态与当前已安装版本分开核对。范围与历史验证证据见 [完整迁移清单](docs/RUST_MIGRATION_MATRIX.md)，Force 历史配置迁移见 [迁移说明](docs/OPENAI_FORCE_MIGRATION.md)。

## 日常使用

- **环境状态**：自动识别代理，核对出口、时区、地区与日期格式、DNS、WebRTC 等检测结果。界面语言可以保持英文，无需手填国家、IP 或 DNS 名单。
- **启动与账号**：通过“检查并启动 Claude”完成完整校验后启动；账号 A/B 保存和载入本地登录资料，空槽显示“未保存”。当前登录识别与本地资料槽分开。
- **后台保护**：显示 Claude Watch 保镖、原版保镖、时区守护与更新任务的实际状态。
- **代理与连接**：Claude 与 ChatGPT / Codex 共用连接关联和历史展示逻辑；按 TAG 的实际 GLOBAL / 规则模式核对路径。
- **事件记录**：Rust 候选版默认显示关键事件，流量采样可单独查看；筛选和搜索覆盖本地当前及上一轮日志。后台持续运行时，流量日志最多每 5 分钟记录一轮，不改变实时采样。DNS、WebRTC 检测摘要仅记录来源、结果、阶段和固定错误类别。环境检测另记录前后的保护判定，以及判定后的心跳附加读取；相同状态最多每 5 分钟重记一次，判定、原因或心跳新鲜度发生变化时会记录。新增摘要不写入地址、节点、登录资料或凭据。完整重置会删除这些日志，排查时先核对需要的证据。

Claude 正常关闭后显示“后台保护待命，无需操作”。异常停止会保留原因；恢复使用时通过“检查并启动 Claude”重新完整校验。

## 安装和更新

使用 `monitor/dist/` 中对应版本的 arm64 DMG。运行包内的 `安装或更新后台.command`，统一替换应用和后台。

安装器校验签名、架构及运行组件哈希，等待旧后台退出后替换；旧应用移入废纸篓，账号和保护设置保留。旧版 Watch 的辅助功能记录会清理，新版首次打开时重新请求系统授权。macOS 的 Touch ID／密码验证由用户完成。

卸载使用包内 `卸载应用.command`。它清理本工具应用、后台任务与辅助功能记录，保留账号资料和原版保镖。直接拖拽删除应用不能代替完整卸载流程。

需要完整重置 Watch 数据后重新安装时，按 [重新安装流程](docs/REINSTALL_WORKFLOW.md) 核对清理范围、打包和安装步骤。

## 构建与验证

依赖本机已有的 Xcode / Swift 和 Python 3.9 以上版本；生产应用目标为 macOS 13 以上。构建不会自动安装或改变系统配置。

```sh
# APP_VERSION 和 BUILD_NUMBER 均须显式指定；以下值仅示例，勿覆盖现有 DMG。
APP_VERSION=3.0.0 BUILD_NUMBER=367 CW_BUILD_ARCH=arm64 bash monitor/package-dmg.sh
```

`package-dmg.sh` **内部会调用 `monitor/build.sh`**，只需执行一次打包命令，避免重复构建。它默认从 Rust 后台清单复制 `watch-process-control`，不再编译并覆盖同名 Swift helper。直接只构建 App 时可使用相同版本环境变量运行 `monitor/build.sh`。两个脚本的默认中间 App 路径统一为 `monitor/build/Claude Watch Monitor Rust Candidate.app`；也可用 `CW_APP_OUTPUT` 自行指定同一个输出路径，例如：

```sh
APP_VERSION=3.0.0 BUILD_NUMBER=367 CW_BUILD_ARCH=arm64 \
CW_APP_OUTPUT="$PWD/monitor/build/Claude Watch Monitor Rust Candidate.app" \
bash monitor/package-dmg.sh
```

打包完成会生成带 SHA-256 校验文件的 DMG；脚本拒绝覆盖同名安装包。**打包不会安装**；安装、删除数据或调整系统权限必须单独授权。

离线 Python 回归测试：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s monitor/tests -v
```

完整源码修复收尾使用以下**无真实进程信号、无账号操作、无安装**的回归入口；它覆盖 Rust 会话/账号/更新隔离测试、Python 构建及策略目录契约、Swift 进程策略用例、生产 SwiftUI 类型检查与 UI_REVIEW 模拟断言：

```sh
bash tools/test-final-no-signal.sh
```

此脚本特意**不执行未经挑选的 `cargo test --workspace`**，因为项目部分历史集成夹具会向自行创建的子进程发送信号；这不属于本轮无信号验收范围。测试全部通过不等同于安装、真实后台保护或真实界面验收。

Swift 测试、隔离界面与真实界面验收说明见 [原生应用开发说明](monitor/README.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `claude-watch.sh` | 采集后台、只读诊断与受控入口 |
| `monitor/Sources/` | SwiftUI 界面、状态模型、连接关联展示 |
| `monitor/Resources/` | WebView 检测页面、辅助脚本、图标资产（不携带已退役的 Python 后台） |
| `monitor/Packaging/` | 完整安装、卸载与权限处理 |
| `monitor/ThirdParty/` | 固定版本的上游源码、来源清单和许可证 |
| `tests/`、`monitor/tests/` | 后台、原生界面和集成测试 |
| `monitor/tools/` | 构建与维护辅助工具 |
| `crates/`、`Cargo.toml` | 已接入的 Rust 策略核心、运行时、原生引擎和安装组件 |
| `tools/rust_shadow.py` | 新旧实现的同输入对照与回放验证 |
| `monitor/build/`、`monitor/dist/` | 可重新生成的构建产物与安装包，不进入 Git |
| `monitor/reports/` | 本机验收和观测记录，不进入 Git |
| `local/` | 本地研究资料、历史文档和维护记录，不进入 Git |

本机真实运行数据位于 `~/Library/Application Support/ClaudeWatch`；Claude 登录资料属于 Claude 自身的数据目录，均不应放入源码仓库。

## 保护边界

- 完整启动校验、运行中的 IP 变化／中国风险／DNS 与 WebRTC 风险拦截、异常锁定和事务回滚保持独立。历史数据与界面绿色状态不授予启动许可。
- 会话保护通过退出 Claude Desktop 生效，有采样和退出延迟；它不是系统防火墙，也不保证账号不会受到服务方限制。
- WebRTC 结果仅覆盖当前检测 WebView；路径动画表示观测到的连接，不表示持续传输或所有安全检查通过。
- 无发布清单和公钥时，自动更新显示不可用，不会从未知来源下载。

实现与模块映射见 [保护与账号设计](monitor/SWITCHER.md)，数据源说明见 [Net.Coffee 接入](monitor/NETCOFFEE.md)，版本摘要见 [CHANGELOG.md](CHANGELOG.md)。

Git 记录从当前源码状态开始建立；安装包、缓存、真实账号、HAR 和本机日志由 `.gitignore` 排除。提交、推送、安装及系统设置修改按各次明确授权执行。
