# Rust 后台完整迁移

完整目标：对照现有成熟功能完成 Rust 后台迁移，发现问题时提供复现依据、解决方案和理由。验收范围以 [完整迁移清单](RUST_MIGRATION_MATRIX.md) 为准，不能用路径判定试点代替整个目标。

Git 基线：`b3a6fcd`；基线时记录的安装版本为 2.9.5 / build 297，本阶段保持既有安装不动。SwiftUI 和必要的 macOS 原生接口保留；业务判定、采样调度、状态持久化、账号事务、恢复和更新迁入 Rust。旧 Python/Bash 可保留为测试参照或薄安装入口，但不能继续执行已宣称迁完的后台业务。

当前进展（2026-10-27）：macOS 监听采样已完成生产修复；安装包内原生组件连续三次使用本机真实 TAG 配置，代理身份、TUN、规则覆盖均通过，退出后无测试进程或采样目录残留。系统 shell 仅提供固定只读原始采样，全部业务判定仍由 Rust 执行。正式后台接管、完整界面与真实保护链路尚未验收，当前安装和账号不动；详细结果见 [完整迁移清单](RUST_MIGRATION_MATRIX.md)。

## 执行计划与规则（2026-10-27，当前约束）

目标是保留成熟能力并完成 Rust 迁移，不照搬旧控制流程。顺序固定为：核准功能清单 → 核准命令接口 → 沿共享服务补齐闭环 → 集成验收 → 获得对应授权后交付。当前安装、账号 A、登录、节点、IP、东京时区、英文环境和两套保镖保持不动；本阶段不提交或推送 Git。

### 固定规则

1. **职责固定**：SwiftUI 只展示与交互；engine 只解析输入、选择服务和输出结果；core 保存共享判定；runtime 负责采样、状态、缓存、事务和受限系统适配。不得在 UI、别名或安装脚本中另设保护规则。
2. **共享判定、区分用途**：代理检查只取代理/TUN/规则证据；DNS 检查读取已有泄漏检测回执与其上下文、采样时间；原始 DNS 路径 probe 不等于泄漏结论。完整预检检查全部启动条件，不把所有命令改成一次全量联网检测。
3. **保护标准冻结**：采样失败不冒充出口变化；历史数据只展示，不授予启动许可；会话 IP 基准由完整受控启动自动建立且不可滚动替换。保留已有异常拦截、超时标准、并发身份核验和回滚，不以“兼容”为由放行未知结果。
4. **不恢复旧流程**：不提供手工 baseline、DNS 名单、allow-changes 或独立启动门禁。旧账号/事务文件的必要读取属于数据恢复，不代表继续执行旧业务。每个迁移项必须有成熟功能、实际调用者和共享服务依据。
5. **操作边界固定**：源码和隔离测试可以实施；安装/卸载、真实账号操作、代理或系统设置修改、Git 提交/推送分别需要对应明确授权。检查成功不等于用户授权，更不等于可以直接部署。
6. **验证与资源控制**：一次完成一个可验证闭环；修改时只跑相关测试，阶段收尾再统一检查。一个主执行者，必要时一名只读审查者；重复失败而无新证据就停止重试并说明原因。不反复打包、不按模块数猜百分比。

### 实施顺序与验收门槛

| 阶段 | 工作与输出 | 通过条件 |
|---|---|---|
| 1. 核准清单 | 对照成熟源码、UI/后台/安装调用者，更新 `RUST_MIGRATION_MATRIX.md`，标明已接入、确定缺口与未验证项 | 功能有去向；历史证据与当前状态分开；不为保留旧名字增加功能 |
| 2. 核准接口 | 固定命令范围、是否联网/保存、错误与退出语义、共享服务及启动权限 | 同一证据解释一致；专项检查不触发无关探测；检查不授予启动许可 |
| 3. 补齐闭环 | 按确定缺口依次补接口、权限、恢复及调用接线 | 正常、失败、过期、并发和恢复场景通过相关测试；无并行旧判定 |
| 4. 集成验收 | 完整 arm64 候选；连续刷新、跨页联动、异常恢复及真实窗口 | 源码、隔离测试、候选包与真实运行分别有证据；一轮绿色不算完成 |
| 5. 交付 | 汇报完整产物、验收结果和未验证项 | 获得对应授权后才替换当前安装；不默认为可以提交 Git |

### 本轮执行结果

- 清单已核准为 M01–M17 的成熟能力及实际调用去向；过期模块进度移入历史证据。
- 主体命令、专项命令和恢复/更新接口已核准；G04a 桌面目标已沿同一 Controller/AuditStore 接入；G04b CLI 生命周期已沿同一控制器接入并隔离验证；未执行真实CLI。
- G01 专项范围、G02 说明中的错误承诺、G03 原生包/更新布局、G06 安装事务门禁与恢复入口已实施，并取得对应隔离证据。
- 上一阶段隔离 arm64 候选通过组件哈希、签名、只读自检与安装预览；本轮 G04a/G04b 完成源码及隔离合同验证，未重新打包、未安装、未操作真实账号、未打开真实应用。完整迁移仍未完成。

### G04 桌面与 CLI 合同（已接线，真实服务未验收）

桌面目标统一使用 launch --target claude-desktop/codex-desktop/chatgpt-desktop；省略 target 保持原 Claude 入口。只有 Claude 目标创建保护会话、固定 IP 基准和失败退出；其他目标只登记现有 LeaseStore 的观察关联，不修改 Claude 会话或账号，不扩大自动退出范围。

其他桌面启动复用 Full AuditStore 的网络、地区、DNS/STUN、规则与风险判定。目标差异由 core 统一描述：观察目标检查采集后台健康，不把 Claude 专属语言、服务或保护开关当成 OpenAI 应用的专属证据；未知和实测风险均不能例外放行。启动每次重新采样并复核出口，检查/专项回执不能授权。观察租约要求支持该格式的原生采集后台，不能用旧后台的健康状态声称观察链已接通。

NativeDesktop 按固定候选位置、精确 bundle 标识和实际可执行文件绑定目标，兼容已知共享 OpenAI 外壳。仅接受应用目录内的等名 bundle 或已知 Homebrew Caskroom 中的等名安装链接，拒绝任意外部链接。已有主进程不补登记，预检完成后再查一次以拒绝预检期间的外部启动；启动后只接受唯一、当前用户、PID/启动身份稳定的目标主进程；超时或身份不明不登记，也不结束其他应用。观察租约仅随实际主进程有效，不等同 Claude 保护会话。

G04a 当前通过：正常/共享外壳、启动失败、已有进程、预检期间外部启动、超时、UID 不符、PID 重用、错误受众和克隆安装链接等隔离场景；主界面14项默认策略仍与成熟实现对照一致。目标审计不覆盖 Claude 页面缓存；来源明确的查询错误和后台状态不会改成出口不一致。

G04b 合同：CLI 使用同一 launch 的 claude-cli/codex-cli 目标，-- 后UTF-8参数按数组原样传给子进程（保留换行等内容，拒绝NUL和超限），不经过 shell、不写入日志。仅对本次 child 提供共享审计确认的 loopback HTTP(S) 代理及 loopback NO_PROXY，清除继承的其他代理变量；不修改父终端、系统、TAG 或配置文件。若 CLI 自身设置会覆盖这条路由且无法核实，明确阻断。第二次出口测量经拟用于 child 的同一入口，仍使用 core 的同轮出口、上下文和 DNS/WebRTC 风险验证，不另设基线或放行规则。

当前CLI实现已验证：启动前Full审计与同轮出口复核、代理设置变化只阻断CLI项、受限来源/文件变化拒绝、PATH和已验证应用内置CLI定位、opaque参数及父子参数分离、wrapper/数据根UID绑定、启动/失败/正常/INT/TERM回收、PID复用失效、无全局revoke、交互时释放共享锁、无额外RPC JSON污染child stdout、参数/配置密钥不进入日志。使用安全signal-hook库处理本进程中断，仅增加锁定的项目依赖，不改系统信号配置。

观察 lease 只标识受控启动及 wrapper 身份，不能充当流量路径通过。--help/--version/交互空闲可以没有连接；实际连接仍只由既有 PID/tuple/TAG 证据判断，不因 lease 而画通过。返回不声称每条 SDK 请求或账号已可用。

startup 在共享 operation/launch 锁内完成审计、owner 身份复核、租约和 spawn；交互 wait 前释放。root/owner 均绑定 wrapper 的完整原生身份。只精确清理本次租约，不 revoke_all；正常退出保留 child 原码和 stdio，INT/TERM 为130/143并转发给本次 child，SIGKILL 后身份立即失效、文件由完整采样回收。观测/路由错误不调用 Claude SessionStore/guard/quit。所有测试使用临时资料和替代 child，不运行真实 CLI。


### 命令接口核准

| 命令/能力 | 范围与唯一服务 | 副作用/权限 | 当前核准结论 |
|---|---|---|---|
| environment | AuditStore 完整环境检测 → 展示回执 | `--online` 联网；`--record` 保存观测；不授予启动许可 | 保留现有 GUI 调用 |
| check/checkdetail、preflight | AuditStore 完整启动要求预检 | 检查回执不授权；实际 launch 仍重新完整审计 | preflight 可作薄名称，不能保留独立预检 |
| proxy-check | 同一 AuditStore 采样/判定中的代理、TUN、规则视图 | 不请求公网 Geo/ASN、STUN 或 AI 服务；不写完整审计缓存；不授权 | 已改专项视图，相关隔离测试通过 |
| dns-check | ReceiptStore 的 DNS 泄漏回执及同轮上下文 → core 同一 DNS 判定 | 默认读共享样本并标时间；显式联网只请求既有 DNS 刷新桥；不跑无关 STUN/ASN/服务检测；不授权 | 已改专项视图，相关隔离测试通过 |
| dns-probe | 原生系统 DNS 路径及 HTTP 参考采样 | 原始诊断，不作为“无泄漏”结论或启动许可 | 保留，与 dns-check 明确区分 |
| audit | AuditStore 完整审计 | 与全量检查使用相同判定；是否保存由接口参数决定；不授权 | 保留 |
| launch/launch-desktop | Controller → fresh full audit → SessionStore → NativeDesktop | 公开启动需 `--apply`；不消费检查回执作许可 | 唯一 Claude 受控启动路径 |
| status/service-status/snapshot | 共享配置、SessionStore、服务状态和已发布观察回合 | 只读；不能由文件存在推断健康 | 保留；会话基准以 SessionStore 为准 |
| account、setup、repair、protection、services、update、安装/卸载 | 各自既有 Rust 事务服务和受限系统适配 | 保留预览绑定、明确执行、读回、冲突处理及恢复 | 已接主体，逐项按清单验证，不在本轮真实执行 |
| AI/评分/服务器参考/通知/进程活动 | 已接网络客户端、采样器和事件服务 | 使用既有缓存、来源与限流；不产生启动权限 | 保留实际调用，按对应协议验证 |
| Codex/ChatGPT 桌面目标 | 同一 Controller / AuditStore / LeaseStore，固定应用身份 | 只登记观察，不修改 Claude 会话和自动退出范围 | G04a 已接入并隔离验证；尚未真实启动验收 |
| CLI 受控启动 | 同一 Controller / AuditStore / LeaseStore 的 wrapper 生命周期 | 参数/stdio/退出码/信号/精确回收已接；子进程代理参考与同轮出口复核 | G04b 源码与隔离闭环通过；未执行真实CLI或账号验收 |

专项命令参数已固定：proxy-check 不接受联网或放行参数；dns-check 默认读取共享泄漏样本，--online 仅调用既有 DNS 刷新接口。返回的原采样时间不会因调用命令而更新；dns_refresh.requested 仅表示请求刷新，不代表已经获得新样本。刷新错误单独展示，不改写样本的出口结论。专项返回不含 ready；退出码 0 表示该范围无失败/未知，3 表示证据未取得或刷新失败，4 表示已检出异常，2 表示参数无效。启动不消费这些退出码作许可。

原生候选使用 RuntimeSchema=2，组件清单只含 watch-engine、watch-native-observer、watch-process-control 和固定 watch-admin.sh 系统适配器；保留来源和许可说明，不打包旧 Python/Bash 业务。原生签名更新的 runtime_schema=2 只替换 app/runtime，并验证两处组件一致；schema-1 的三根事务仅保留恢复兼容。未完成安装统一进入维护恢复门禁；只有内部 maintenance 协调入口可以先恢复安装，其他类型恢复不能借恢复标记越过它。多份记录出现指纹冲突时停止并保留证据，不自动覆盖。

所有检测结果应说明观察编号、上下文、采样时间、来源与失败原因。未取得、已过期、历史有效和实测异常必须区分；退出码与返回字段的具体合同由对应专项测试固定，不在入口重写业务判定。

当前误加的旧独立基线/预检/启动模块已删除。初始化事务的 `environment_capture` 仅采集本机设置并保留既有恢复编码；它不参加启动判断。持续记录复用 `local/maintenance/rust-refactor-progress.json`，不新建同目标任务记录。

## 已迁入模块与尚未完成的接入

检测、会话保护、账号事务、环境初始化与恢复、服务及更新主体已接入 Rust 引擎；原生采样后台、网络工具和 SwiftUI 数据协议已有隔离验证。其他桌面目标已完成共享服务接线与隔离验证，CLI 生命周期已完成共享服务接线与隔离验证；完整候选包、连续真实窗口和异常恢复验收尚未完成，当前不能发布为完整 Rust 版。

最初路径阶段曾通过80项 Rust 测试、70项原版TAG回归和3,028组 TAG 路径对照；这些是历史证据，不作为当前集成版本的测试总数。当前验证和剩余事项见持续记录。

## 最初的路径判定对照

首个模块是 TAG `connection_policy`：在连接已经完成身份、源端口、时间、TUN / fake-IP 关联之后，核对实际模式、完整选择链和显式节点要求。

- `crates/watch-core/`：纯业务函数库，序列化用于跨模块数据契约；禁止 unsafe，不访问文件、网络、时钟或进程。
- `crates/watch-runtime/`：持久化、共享操作锁及运行时协调，使用明确的数据根目录和系统适配接口。会话状态机已开始接入真实文件存储，不再局限于 shadow 输出。
- `crates/watch-shadow/`：stdin/stdout JSON Lines 适配器，只做只读对照。没有 apply、启动、退出、安装或账号操作。
- `tools/rust_shadow.py`：从当前 Bash 内嵌 Python 中只提取原纯函数，使用同一份输入比较状态与原说明文字。不会执行 Bash 或整个 Python 适配器。
- `crates/watch-core/tests/fixtures/tag-policy-v1.json`：28 个可审阅的边界样例；另外生成固定种子的 3,000 个组合样例。

判定顺序与现有实现保持一致：模式不可取得、直连／拒绝路径、空链、显式 GLOBAL 分组冲突、规则缺失、选择链缺失、节点／完整链差异，最后才是匹配。`match` 仅代表该项链核对，不代表网络无泄漏、进程身份可信或可以启动 Claude。

## 协议 v1

必须显式使用 `--shadow`，每行一个请求，每行一个响应；输入上限 64 KiB、128 个选择链、每链 16 个节点。未知字段、重复键、非法类型、控制字符和不支持的版本都会拒绝。错误响应不回显输入内容，错误帧之后的完整请求仍可处理。

```json
{"schema_version":1,"request_id":"example-1","operation":"tag_connection_policy","evidence":{"observed_chain":["JP-test","GLOBAL"],"required_group":"","pinned_node":"","matched_rule":null,"api":{"state":"available","mode":"global","route_chains":{"GLOBAL":["JP-test","GLOBAL"]}}}}
```

响应始终带 `mode: "shadow"` 和 `grants_launch_permission: false`。成功响应包含 `result.state`、稳定原因代码及兼容原实现的文字；格式或资源限制错误包含 `error`，不提供判定。

这不是后台与 UI 的最终 IPC 协议。当前接口不接收账号文件、controller secret、网络地址凭据或执行命令，也不具备发布保护状态的权限。

## 验证

工具链固定为官方 Rust 1.99.1，使用 arm64 主机工具链。Cargo.lock 由 Cargo 生成并保留，不手工填写依赖校验值。安装时不修改 shell 配置；检查脚本会查找 PATH 或 `~/.cargo/bin/cargo`。

```sh
bash tools/check-rust-shadow.sh \
  --report local/maintenance/rust-shadow-initial.json
```

脚本执行格式检查、Rust 单元测试、Clippy、整个Rust工作区的release构建和差分测试；当前只生成库及shadow程序，不生成正式后台安装包。依赖已写入 Cargo.lock，常规验证使用 `--locked`。`target/` 为忽略的构建目录，Rust 工具不进入现有 DMG。只验证 Python 对照工具时不需要 Rust：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_rust_shadow_harness.py' -v
```

可选的本机快照回放：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/rust_shadow.py \
  --snapshot "$HOME/Library/Application Support/ClaudeWatch/state/proxy-snapshot.json" \
  --report local/maintenance/rust-shadow-snapshot.json
```

快照一次性读取，只比较已关联连接；不会重新联网或查询 TAG。仅提取模式、链、显式要求与命中规则，报告保存快照哈希而不导出完整快照或账号信息。历史快照回放不代表当前网络安全。

通过条件：固定样例和组合样例零差异；畸形帧、超限、错误版本、无 apply 权限与进程失败处理通过；原 TAG 关联测试不退化。记录的 Python 纯函数时间与 Rust 进程/JSON 总耗时边界不同，不作为生产性能结论。

## 2026-10-26 最初路径模块验证记录（历史）

- Rust 1.99.1 arm64：格式检查、9 项单元测试、Clippy（警告视为错误）与 release 构建通过。
- 28 个固定边界样例与 3,000 个确定性组合，状态及原说明文字零差异；8 项协议/启动参数故障检查通过。
- 回放当次本机快照中的 19 条已关联连接，与相同 Python 函数逐项一致。此为已有数据回放，没有发起新网络检测。
- 8 项 Python 对照工具测试、51 项原 TAG 测试和 19 项原 TUN/fake-IP 测试通过。
- 正式后台、SwiftUI、账号与保护实现相对 Git 基线未修改，安装包和系统服务没有替换。Rust 工具链安装前后的 shell 配置哈希一致。

本机详细结果位于忽略目录 `local/maintenance/rust-shadow-final.json`、`rust-shadow-snapshot.json` 和 `rust-toolchain-install.json`。这完成第一模块的行为对照，不代表常驻服务、整体性能或生产替换已验收。

## 持续实施与完成标准

按照清单持续迁入全部模块，逐项移植现有场景和失败恢复测试。源码层面必须由 Rust 承担完整后台业务，SwiftUI 必须接入 Rust 的正式接口，候选安装包必须包含完整运行组件；仅代码存在、命令返回成功或少量单元测试不能证明全量迁移完成。

测试写入使用隔离资料目录，实际保护仍由已安装后台承担；不能让两个自有版本同时控制真实账号或执行拦截。账号存档、事务恢复和进程控制必须有失败注入、旧 journal 兼容与回滚证据。正式服务切换、安装应用和 Git 提交按各次明确授权执行。完整目标在清单全部有充分证据前保持进行中。

本地候选打包：`monitor/build.sh` 默认仍构建 `stable` 旧后台包。只有明确设定 `CW_BACKEND_VARIANT=rust-candidate CW_BUILD_ARCH=arm64` 才会调用 `tools/build-rust-components.sh`，将 Cargo 的 `claude-watch-engine` 和由该引擎 `--component-paths` 返回的两个原生组件一同放入候选 `.app`；组件缺失、路径不安全或校验不一致会中止构建。候选在 `BuildInfo.plist` 标记为 `rust-candidate`，不是发布包，不能据此进行安装、服务切换或声称完整迁移已经发布。
