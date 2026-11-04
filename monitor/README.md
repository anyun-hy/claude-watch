# 原生应用开发说明

源码构建版本与 build 号由调用者显式指定；不能用仓库文档推断当前安装版本。日常使用与安装说明见 [项目首页](../README.md)。

## 源码入口

| 文件或目录 | 职责 |
| --- | --- |
| `Sources/MonitorApp.swift` | 导航、工具栏、概览 |
| `Sources/MonitorStore.swift` | 观察协调、后台轮询、界面共享状态，不再负责快照子进程执行 |
| `Sources/MonitorSnapshotReader.swift` | 独立快照命令执行与 JSON 解码，不包含用户会话授权 |
| `Sources/DiagnosticContextTracker.swift`、`MonitorPage.swift` | 诊断上下文时效与页面定义 |
| `../crates/watch-runtime/src/controlled/launch.rs` | 受控启动、观察租约与 CLI 生命周期 |
| `../crates/watch-runtime/src/controlled/sampling_failure.rs` | Guard 采样失败后的独立恢复分支 |
| `Sources/SessionProtectionPresentation.swift` | 会话状态与最新只读证据的统一展示 |
| `Sources/SessionBaselinePresentation.swift` | 自动会话基准及历史记录展示 |
| `Sources/SwitcherStore.swift`、`SwitcherPage.swift` | 环境、启动与账号、后台保护页面 |
| `Sources/ConnectionGraphModel.swift`、`GraphDisplayState.swift` | 连接投影、当前／历史路径状态 |
| `Sources/ConnectionInventory.swift` | 按应用、平台、MCP、本地和组件用途归类 |
| `Sources/ClaudeLoginProbe.swift`、`AccessibilityPermission.swift` | 只读账号界面识别与系统授权请求 |
| `Sources/BundledBackendVariant.swift` | 运行时仅使用 Rust 引擎，不依赖已退役 Python 后台 |
| `../crates/watch-runtime/`、`../crates/watch-engine/` | 账号、会话保护、更新与恢复的 Rust 运行时和命令入口 |
| `Packaging/` | 应用替换、后台安装、卸载与权限生命周期 |

## 构建

从项目根目录执行：

```sh
# 仅构建 App（值仅为示例）
APP_VERSION=3.0.0 BUILD_NUMBER=367 CW_BUILD_ARCH=arm64 bash monitor/build.sh
# 打包 DMG 时会自动执行构建，避免再单独运行上一命令：
APP_VERSION=3.0.0 BUILD_NUMBER=367 CW_BUILD_ARCH=arm64 bash monitor/package-dmg.sh
```

策略目录仅在 `crates/watch-core/src/policy.rs` 定义。修改 Rust 策略项、动作或默认值后运行 `python3 tools/generate-ai-policy-swift.py --write` 更新生成文件；构建前会强制执行 `--check`，防止 Swift UI 与 Rust 授权规则不一致。UI 源文件只维护中文展示文字。

本地构建使用临时签名，未提供 Developer ID 公证。`build/` 和 `dist/` 均为生成目录，可以清理；清理不影响 `/Applications` 中已安装的应用。需要另设输出目录时可使用 `CW_APP_OUTPUT`。

## 离线验证

Python 测试入口见项目首页。Swift 状态测试使用当前 macOS SDK，编译目标由 `macos-minimum.txt` 决定（当前为 macOS 26.0；不要与历史 macOS 13 声明混淆）：

```sh
mkdir -p /private/tmp/claude-watch-tests/module-cache
xcrun swiftc -swift-version 5 -Onone -parse-as-library -D UI_REVIEW \
  -target arm64-apple-macosx$(cat monitor/macos-minimum.txt) \
  -module-cache-path /private/tmp/claude-watch-tests/module-cache \
  -framework SwiftUI -framework AppKit -framework WebKit \
  monitor/Sources/*.swift monitor/tests/SwitcherStoreTests.swift \
  -o /private/tmp/claude-watch-tests/switcher-tests
/private/tmp/claude-watch-tests/switcher-tests
```

`UI_REVIEW` 模式隔离真实账号、系统设置和权限请求。其他 Swift 用例位于 `tests/`；不要同时编入多个带 `@main` 的测试入口。

隔离界面：

```sh
UI_REVIEW_OPTIMIZATION=-Onone bash monitor/tests/build_ui_review.sh
```

打开生成的 `build/Claude Watch UI Review.app`；标题会标明模拟数据。它用于布局和状态转换检查，不等同于安装版或真实网络验收。

原生 WebView 桥接测试默认只编译。仅在已获授权且可使用 macOS 图形会话的环境下运行 `tests/run_leak_bridge_test.sh --run`，避免在受限沙盒中反复触发系统崩溃弹窗。

## 实机验收

安装后核对实际版本、后台心跳、权限与保留的数据，再检查真实界面。连接页需连续观察正常请求、空采样和恢复；会话显示需覆盖运行中、正常关闭待命与真实异常锁定。不能以一轮绿色结果或模拟窗口代替真实验收。

本机验收材料保存到忽略目录 `reports/`。当前保留 `build297-install.json`；原始观测、IP、进程和账号信息不进入 Git。

## 资源与上游

上游代码位于 [ThirdParty/ClaudeSwitcher](ThirdParty/ClaudeSwitcher/UPSTREAM.json)，其 [MIT 许可证](ThirdParty/ClaudeSwitcher/LICENSE) 和来源哈希必须保留。图标及国旗的来源和许可位于 `Resources/Icons/` 与 `Resources/Identity/`。不要把编译出的 `.app` 当作源码提交。
