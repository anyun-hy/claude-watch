# Claude Watch

macOS 上的 Claude 受控启动、账号 A/B 切换与环境保护工具，同时观察 Claude、ChatGPT / Codex 的进程和代理连接。

当前源码版本：**应用 2.9.5 / build 297，后台 2.8.4**。当前发行目标为 **Apple Silicon（arm64）**。

## 日常使用

- **环境状态**：自动识别代理，核对出口、时区、地区与日期格式、DNS、WebRTC 等检测结果。界面语言可以保持英文，无需手填国家、IP 或 DNS 名单。
- **启动与账号**：通过“检查并启动 Claude”完成完整校验后启动；账号 A/B 保存和载入本地登录资料，空槽显示“未保存”。当前登录识别与本地资料槽分开。
- **后台保护**：显示 Claude Watch 保镖、原版保镖、时区守护与更新任务的实际状态。
- **代理与连接**：Claude 与 ChatGPT / Codex 共用连接关联和历史展示逻辑；按 TAG 的实际 GLOBAL / 规则模式核对路径。

Claude 正常关闭后显示“后台保护待命，无需操作”。异常停止会保留原因；恢复使用时通过“检查并启动 Claude”重新完整校验。

## 安装和更新

使用 `monitor/dist/` 中对应版本的 arm64 DMG。运行包内的 `安装或更新后台.command`，统一替换应用和后台。

安装器校验签名、架构及运行组件哈希，等待旧后台退出后替换；旧应用移入废纸篓，账号和保护设置保留。旧版 Watch 的辅助功能记录会清理，新版首次打开时重新请求系统授权。macOS 的 Touch ID／密码验证由用户完成。

卸载使用包内 `卸载应用.command`。它清理本工具应用、后台任务与辅助功能记录，保留账号资料和原版保镖。直接拖拽删除应用不能代替完整卸载流程。

## 构建与验证

依赖本机已有的 Xcode / Swift 和 Python 3.9 以上版本；生产应用目标为 macOS 13 以上。构建不会自动安装或改变系统配置。

```sh
CW_BUILD_ARCH=arm64 bash monitor/build.sh
CW_BUILD_ARCH=arm64 bash monitor/package-dmg.sh
```

第一条生成 `monitor/build/Claude Watch Monitor.app`，第二条生成带 SHA-256 校验文件的 DMG。打包脚本拒绝覆盖同名安装包。

离线 Python 回归测试：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s monitor/tests -v
```

Swift 测试、隔离界面与真实界面验收说明见 [原生应用开发说明](monitor/README.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `claude-watch.sh` | 采集后台、只读诊断与受控入口 |
| `monitor/Sources/` | SwiftUI 界面、状态模型、连接关联展示 |
| `monitor/Resources/` | Python 保护与账号引擎、检测页面、图标资产 |
| `monitor/Packaging/` | 完整安装、卸载与权限处理 |
| `monitor/ThirdParty/` | 固定版本的上游源码、来源清单和许可证 |
| `tests/`、`monitor/tests/` | 后台、原生界面和集成测试 |
| `monitor/tools/` | 构建与维护辅助工具 |
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
