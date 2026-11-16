# 协议与不变量

## 1. 信封

两个 token 类型共用同一信封：

```
BASE64URL({"alg":"HS256","typ":"JWT"}) . BASE64URL(payload) . BASE64URL(HMAC-SHA256)
```

* header 必须**恰好**是 `{"alg":"HS256","typ":"JWT"}`（两个成员、无其它）。
  出现 `jku` / `jwk` / `x5u` / `kid` / `crit` 即 `401 invalid_header`——
  不是“忽略”，是拒绝。票据无法影响密钥选择。
* payload 必须是无重复成员的严格 JSON 对象；`NaN`/`Infinity` 拒绝。
* 签名比较恒定时；长度不等直接失败。

## 2. 登录票据

```json
{
  "iss": "https://idp-alpha.test",
  "sub": "alice",
  "sid": "s-...",
  "generation": 3,
  "aud": "rp-test",
  "exp": 1794868518,
  "iat": 1794864918                // 可选，仅签发时间，不参与任何判定
}
```

校验顺序（Fail closed）：

1. 结构/JSON 严格性/header 精确匹配
2. `iss` 必须命中预置配置（未知 issuer 在验签**之前**拒绝）
3. 用预置密钥验签
4. `exp` 必须存在、为整数、未过期（允许配置的 `clock_skew_seconds`）
5. `aud` 必须等于配置的 audience
6. `sub` 必须在该 issuer 的预置 subject 列表内
7. `sid` 非空、无空白/控制字符
8. `generation` 必须是 JSON 整数且 `>= 1`（`true`/`"1"`/`1.0` 均拒）

身份键是 `(iss, sub)`。`alice@alpha` 与 `alice@beta` 是两个人。

## 3. 登出通知

两种形状，`type` 区分，都用独立的登出签名密钥（与登录密钥不同）：

```json
// 单 sid
{"v":1,"event_id":"ev-1","iss":"alpha-logout","type":"sid",
 "target_iss":"https://idp-alpha.test","sub":"alice","sid":"s-...",
 "iat":...,"exp":...}

// 范围
{"v":1,"event_id":"ev-2","iss":"alpha-logout","type":"range",
 "target_iss":"https://idp-alpha.test","sub":"alice","cutoff_generation":7,
 "iat":...,"exp":...}
```

* `type=sid` 不得携带 `cutoff_generation`；`type=range` 不得携带 `sid`
  （`invalid_shape`）——避免“同一事件两种解释”。
* `cutoff_generation` 是整数且 `>= 0`。
* `v` 必须为整数 1。

### 3.1 语义摘要（冲突判定）

`event_semantic_digest = SHA256(canonical(event_id, iss, type, target_iss,
sub, sid, cutoff_generation))`。

**排除 `iat`/`exp`**：通知方在重试时重新签名同一事件（新有效期）属于
重传而非语义变更，必须幂等接受。任何改变撤销范围的字段都包含在内，
因此“同 id 不同目标/不同 cutoff”必然 `409 event_conflict`。

## 4. 持久状态

```sql
subjects(iss, sub, cutoff_generation)         -- 单调水位，PK(iss,sub)
sid_revocations(iss, sid, reason_event)       -- 永久击杀，PK(iss,sid)
sessions(session_id, iss, sub, sid, generation, ..., revoked, revoke_kind)
seen_events(event_id, event_iss, body_sha256, applied)
meta('revocation_epoch', N)
```

### 4.1 应用范围登出（`cutoff=K`）

```
new_watermark = max(stored_watermark, K)
UPDATE sessions SET revoked=1, revoke_kind='range'
  WHERE iss=? AND sub=? AND generation <= new_watermark AND revoked=0
```

注意撤销用的是**新水位**而不是本次 `K`：迟到的低 `K` 通知出现时，
它虽然不推进水位，但仍会按当前（更高）水位补刀，绝不会留下漏洞。

### 4.2 应用单 sid 登出

```
INSERT OR IGNORE INTO sid_revocations(iss, sid, reason_event)
UPDATE sessions SET revoked=1, revoke_kind='sid' WHERE iss=? AND sid=? AND revoked=0
```

`sid_revocations` 允许 sid 从未出现过；这正是“先登出后票据”能生效的原因。

## 5. 不变量与论证

### I1. 被水位覆盖的会话不可用

登录在 `BEGIN IMMEDIATE` 内**同一事务**读取水位并插入。设登录提交时刻为
`t_L`，覆盖它的范围登出提交时刻为 `t_O`：

* `t_L < t_O`：登出的 `UPDATE ... generation <= watermark` 命中该行；
* `t_O < t_L`：登录在同一事务中看到水位（SQLite 单写者保证不会有人在
  其间插入第三个写事务），直接拒绝或写入 `revoked=1`。

两者都是写事务，SQLite 提供全序，不存在第三种情况。

### I2. 登出响应之后开始的鉴权不会放行

`revocation_epoch` 在同一写事务中自增；响应在提交**之后**才发出。
鉴权流程先无条件读 epoch 再查缓存。设鉴权开始时刻 `t_A > t_ack`：
此时 epoch 提交已完成，该进程要么读到新 epoch（缓存失效→查库→拒绝），
要么读到更晚的 epoch（同样失效）。缓存命中只在 epoch 相同时发生。
缓存项的会话若是已撤销的旧结论——不可能，因为它记录的 epoch 更旧了。

> 缓存的放行结论只在 epoch 不变期间有效；epoch 是**单调计数器**，
> 不会回绕到曾用过的值（进程重启不清零，存在 `meta` 表里）。

### I3. 重复投递不改变状态

第二次投递命中 `seen_events` 且摘要一致 ⇒ `duplicate`，跳过事务 B，
epoch 不变（测试断言了这一点）。因此重复通知既不推进水位也不推进 epoch。

### I4. 同 id 不同内容不被施加

摘要不一致 ⇒ `409` 且事务 A 回滚（不插入）。两份内容都不会生效，
必须由运维解决 id 冲突。

### I5. 崩溃不产生“已确认但未撤销”

* `logout.after_dedup` 崩溃：事务 A 已提交（`applied=0`），事务 B 未开始，
  HTTP 响应未发出。调用方未获确认，重发时 `_apply_phase` 看到
  `applied=0` 而重做。
* `logout.after_commit` 崩溃：事务 B 已提交（撤销持久），响应未发出。
  重发命中 `applied=1` ⇒ `duplicate`，状态不变。
* HTTP 层只在 `receive_logout` 正常返回后写 2xx；任何异常都不会走到
  `_respond`。

结论：**2xx 已返回 ⇒ 撤销已提交**；**未返回 ⇒ 状态可从磁盘恢复重做**。

### I6. 同 sid 重试不重置撤销

会话查找按 `(iss, sid)`。已存在的行只被读取，不被更新。若已撤销，
返回 `409 state=revoked`，`revoked`/`revoked_by` 原样保留。

### I7. 不同 issuer 不串扰

所有键都是 `(iss, ...)`。`sid_revocations` PK 是 `(iss, sid)`；
`subjects` PK 是 `(iss, sub)`；`sessions` 有 `iss` 列且唯一约束是
`(iss, sid)`。

## 6. 并发模型

* 写：`BEGIN IMMEDIATE`（SQLite 全局写锁）⇒ 全序。
* 读（鉴权）：`BEGIN`（deferred，WAL 快照）⇒ 看到某个写事务前缀。
* `busy_timeout=30s`，够慢事务拿锁。
* 同步点写入 `hooks` 表，`DELETE ... RETURNING` 单语句原子消费；
  在持读事务时通过**独立连接**消费，避免写锁与快照互等。

## 7. 已知边界

* 单写者 ⇒ 吞吐上限是 SQLite 写锁；本题规模足够。
* 时钟：`clock_skew_seconds` 默认 0，测试不依赖宽松时钟。
* `/admin/*` 无鉴权，只绑本机。
