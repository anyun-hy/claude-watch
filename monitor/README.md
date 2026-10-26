# 原生应用开发说明

应用版本 **2.9.5 / build 297**，后台 **2.8.4**。日常使用与安装说明见 [项目首页](../README.md)。

## 源码入口

| 文件或目录 | 职责 |
| --- | --- |
| `Sources/MonitorApp.swift` | 导航、工具栏、概览 |
| `Sources/MonitorStore.swift` | 采集刷新、页面共享状态 |
| `Sources/SessionProtectionPresentation.swift` | 会话状态与最新只读证据的统一展示 |
| `Sources/SessionBaselinePresentation.swift` | 自动会话基准及历史记录展示 |
| `Sources/SwitcherStore.swift`、`SwitcherPage.swift` | 环境、启动与账号、后台保护页面 |
| `Sources/ConnectionGraphModel.swift`、`GraphDisplayState.swift` | 连接投影、当前／历史路径状态 |
| `Sources/ConnectionInventory.swift` | 按应用、平台、MCP、本地和组件用途归类 |
| `Sources/ClaudeLoginProbe.swift`、`AccessibilityPermission.swift` | 只读账号界面识别与系统授权请求 |
| `Resources/snapshot.sh`、`snapshot.py` | 只读后台数据适配 |
| `Resources/watch_switcher/` | 账号、环境、会话保护、更新和恢复引擎 |
| `Packaging/` | 应用替换、后台安装、卸载与权限生命周期 |

## 构建

从项目根目录执行：

```sh
CW_BUILD_ARCH=arm64 bash monitor/build.sh
CW_BUILD_ARCH=arm64 bash monitor/package-dmg.sh
```

本地构建使用临时签名，未提供 Developer ID 公证。`build/` 和 `dist/` 均为生成目录，可以清理；清理不影响 `/Applications` 中已安装的应用。需要另设输出目录时可使用 `CW_APP_OUTPUT`。

## 离线验证

Python 测试入口见项目首页。Swift 状态测试需要 macOS 14 以上的本机工具链环境：

```sh
mkdir -p /private/tmp/claude-watch-tests/module-cache
xcrun swiftc -swift-version 5 -Onone -parse-as-library -D UI_REVIEW \
  -target arm64-apple-macosx14.0 \
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
