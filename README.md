# 运动员网络权益保护

围绕赛事参与者遭遇网络侵害后的**受理、保护、复核与协同处置**建立统一服务，替代截图+群聊报送：当事人或授权代理提交线索后，系统按严重度分流立案，组织受控证据、平台回执、威胁等级与关联账号，并把每个保护动作的责任落到具体角色。

## 核心规则

- **严重度分流**：普通批评（criticism）只登记线索观察、不立事件；一般网暴（abuse）立案常规处置；直接人身威胁（direct_threat）立案即按值班规则升级，通知值班主管与保护专员。
- **受控证据**：原始内容不入库，只保存内容引用（URL）与 SHA-256 哈希；证据补充同样只收引用。
- **责任链不可变**：内容删除、账号改名、证据补充、授权撤回均只追加事件（JSONL 账本），不覆盖旧记录，任意时刻可还原全过程。多个事实按事务整组提交（账本中每个事务一行，flush+fsync）；进程在写入点中断后，撕裂的尾部行会被封存到 `.quarantine`，动作可凭幂等索引安全重做。
- **自动聚类只建议**：同当事人+同内容哈希、或共享关联账号时生成合并建议，须保护专员人工确认才合并。
- **职责分离**：平台投诉→平台联络员复核；报案、公开澄清→法务复核员复核；提交人不得复核自己发起的动作。
- **授权驱动**：当事人当前授权不足时，已批准的对外动作保持 blocked；撤回授权不抹除已完成动作与既有责任链；申诉/司法程序存续期间证据留存授权不可撤回。
- **回调幂等与原子性**：平台回调以 `callback_id` + **内容指纹**去重；一个回调涉及的回执、内容状态、账号关系与已处理标记在**同一账本事务**中同生共死。完全相同的重传返回首次结果（`duplicate=true`）；同标识异内容返回 `409` 冲突且不回显任何敏感正文、不做任何写入。并发同标识请求只有一个胜者。事件被合并或关闭后，迟到回调归入责任链主事件（响应中以 `routed_from` 标明原指向），不重开旧事件、不通知、不另立案件。
- **误报申诉**：申诉期间事件置"申诉中"，敏感材料仅法务复核员与值班主管可见，并阻断新的对外动作。
- **直接威胁去重**：同一事件值班周期内重复确认威胁等级只刷新确认时间，不产生第二案件或第二次通知。

## 运行

```bash
python3 service.py --check          # 检查配置与可重放账本
python3 service.py --port 8000      # 内存账本（联调）
python3 service.py --data data/events.jsonl   # 追加式持久化账本（重启可重放）
npm test                            # 全部契约与可靠性测试（47 项）
```

## HTTP 接口

所有写操作在请求体携带 `actor: {"name","role"}`；角色取值见 `fixtures/domain.json`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` `/domain` | 健康检查、领域配置（角色/严重度/动作/规则） |
| POST | `/reports` | 报送线索；按严重度决定不立案或开新事件并返回 `incident_id` |
| POST | `/severity/suggest` | 联调辅助：按文本给严重度建议（不替代人工判定） |
| GET | `/reports` `/incidents` `/suggestions` `/notifications` | 列表（支持 status/severity/as_role 过滤） |
| GET | `/incidents/{id}/digest?as_role=…` | **保护专员统一视图**：证据依据、处置决定、当事人当前授权范围、尚未完成的保护动作、值班升级、责任链 |
| POST | `/incidents/{id}/severity` | 保护专员确认/调整严重度 |
| POST | `/incidents/{id}/escalation/ack` | 值班主管响应升级 |
| POST | `/incidents/{id}/evidence` | 补充受控证据（只收 `content_ref` + 可选哈希） |
| POST | `/incidents/{id}/accounts` | 登记关联账号 |
| POST | `/incidents/{id}/actions` | 发起处置动作（返回所需复核角色） |
| POST | `/actions/{id}/review` `/actions/{id}/execute` | 分角色复核、复核通过后执行（执行时再次校验授权） |
| POST | `/incidents/{id}/consent/grant` `/consent/revoke` | 当事人代理授予/撤回授权 |
| POST | `/incidents/{id}/appeal` `/appeal/resolve` | 发起误报申诉、法务裁定（upheld/dismissed） |
| POST | `/suggestions/{id}` | 保护专员 accept/reject 合并建议（accept 时给 `target_incident`） |
| POST | `/callbacks/platform` | 平台/采集回调（幂等键 `callback_id` + 内容指纹；可携带回执、删除状态、改名信息；整组事务落账；同标识异内容 409） |
| POST | `/incidents/{id}/close` | 关闭事件（存在未响应升级或未完成动作时拒绝） |

## 代码结构

- `fixtures/domain.json` — 角色、严重度、授权范围、处置动作、值班规则、聚类/申诉规则、平台与回执样例
- `domain.py` — 领域配置加载与校验
- `store.py` — 线程安全的追加式事件账本（内存或 JSONL，事务原子提交、fsync、撕裂尾部封存、重放恢复）
- `app.py` — 业务核心：受理立案、升级、证据/账号、聚类、动作复核、授权、申诉、幂等回调（指纹冲突、并发单胜者、责任链路由）、统一视图
- `service.py` — HTTP 入口
- `service_contract.py` / `test_safeguarding.py` — 基础契约与全链路测试
- `test_callback_reliability.py` — 回调可靠性测试：故障注入（提交前/撕裂/提交后崩溃）、并发单胜者、合并/关闭路由、重启一致性

## 构建检查

```bash
python3 -m compileall -q .
```
