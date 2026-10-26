# Net.Coffee 数据接入

实现入口为 `Sources/NetCoffeeStore.swift`、`NetCoffeeLeakRunner.swift`、`NetCoffeeScorePage.swift`，以及 `Resources/netcoffee_client.py` 和 `netcoffee_probe.*`。

## 用途

- IP 评分与网络归属复用已有查询结果，保留原来源、时间和缺失字段。
- DNS 检测通过随机域名取得权威查询记录，并与同轮 HTTP 公网出口比较。DNS 递归 IP 与 HTTP IP 不要求完全相同；当前策略核对国家／地区。
- WebRTC 在检测 WebView 中采集结构化 ICE 公网候选，与同轮 HTTP 出口比较；mDNS 与非公网候选单独处理。
- AI 服务诊断的 HTTP 出口、浏览器检测出口与真实应用连接是不同证据，不互相冒充。

当前环境页面会协调自动检测与后台刷新，DNS、WebRTC 和环境判定复用回执；它不是早期仅手动检测的实现。采样失败、查询限流、空结果和超时保留具体原因，不能直接判作“无泄漏”。

这些接口来自第三方网站，稳定性由上游决定。IP 评分不代表账号可用性；WebRTC 结果也不能替所有应用保证无泄漏。

## 验证与资料

离线测试位于 `tests/test_netcoffee_client.py`、`test_netcoffee_probe.cjs`、`NetCoffeeTests.swift` 及相关泄漏回执测试。

`tests/run_netcoffee_live_check.sh` 是明确联网的原生开发验收入口，会写本机报告；需要单独授权运行。`tests/build_ui_review.sh` 使用隔离样本，历史样本保留原时间。

实时验收材料位于忽略目录 `reports/netcoffee/`。早期网页脚本、REA 输出与研究包集中到根目录的 `local/research/netcoffee-20261019/`；这些资料不作为运行依赖，也不进入 Git。旧说明移到 `local/archive/`。
