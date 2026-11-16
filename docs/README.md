# 本地 SSO 会话接入与后台登出接收服务（Windows / Python 3.12 标准库）

> **这不是 OIDC。** 本仓库实现的是题目中明确约定的“测试协议”：固定 HS256 票据、
> 预置 issuer 元数据、两种后台登出通知。没有 discovery、没有授权码流程、
> 没有 token introspection，也不声称符合任何 OIDC 规范条文。

所有交互走真实 HTTP（`127.0.0.1`）。没有 Docker，没有外部账号，只用
Python 3.12 标准库 + SQLite + CPU。

---

## 1. 快速开始（Windows）

```bat
set PY=D:\CC_Codex_FeedBack\runtimes\cc005-csv-python312\python.exe

%PY% -m sso_local init --db data\rp.db
%PY% -m sso_local idp  --config config\local.json --state data\idp-state.json --port 8081
%PY% -m sso_local rp   --db data\rp.db --config config\local.json --port 8082
```

另起一个控制台（模拟普通用户）：

```bat
set PY=D:\CC_Codex_FeedBack\runtimes\cc005-csv-python312\python.exe

:: 1) IdP 签发登录票据
%PY% -m sso_local ticket --config config\local.json --state data\idp-state.json ^
     --iss https://idp-alpha.local --sub alice

:: 2) 拿票据换本地会话
%PY% -m sso_local login --rp http://127.0.0.1:8082 --ticket "<上一步的 ticket>"

:: 3) 调受保护接口
%PY% -m sso_local check --rp http://127.0.0.1:8082 --session-id "<session_id>"

:: 4) IdP 造登出通知，推给 RP
%PY% -m sso_local logout-event --config config\local.json --event-id ev-1 ^
     --type sid --target-iss https://idp-alpha.local --sub alice --sid "<sid>"
%PY% -m sso_local logout-send --rp http://127.0.0.1:8082 --logout "<上一步的 logout>"

:: 5) 再调一次，应得 401 revoked:sid
%PY% -m sso_local check --rp http://127.0.0.1:8082 --session-id "<session_id>"

:: 6) 看状态
%PY% -m sso_local status  --rp http://127.0.0.1:8082
%PY% -m sso_local summary --db data\rp.db
```

多进程（题目要求至少 4 个 RP 共享一个库）：

```bat
%PY% -m sso_local rp --db data\rp.db --config config\local.json --port 8082
%PY% -m sso_local rp --db data\rp.db --config config\local.json --port 8083
%PY% -m sso_local rp --db data\rp.db --config config\local.json --port 8084
%PY% -m sso_local rp --db data\rp.db --config config\local.json --port 8085
```

任何一个进程都能接登录、接登出、做鉴权；状态全部在 SQLite 里，进程本身
只缓存“放行”结论。

### 一键演示脚本

```bat
scripts\demo.bat            :: 起 IdP + 4 RP，跑一遍乱序/重复登出，打印结果后退出
scripts\run_tests.bat       :: 跑全部自动化测试（约 1 分钟）
```

> `scripts\*.bat` 里同样读取 `PY`（若未设置则回退到 `python`）。

---

## 2. 架构

```
            ┌──────────────┐   登录票据 (HS256)   ┌────────────────────────┐
            │ IdP 模拟器   │ ───────────────────► │ RP 进程 × N            │
            │ :8081        │                      │ :8082..:8085           │
            │ 代数计数     │   登出通知 (HS256)   │ 无状态 HTTP handler    │
            │ sid 不复用   │ ───────────────────► │        │               │
            └──────────────┘                      └────────┼───────────────┘
                                                          │ BEGIN IMMEDIATE
                                               ┌──────────▼───────────┐
                                               │  SQLite (WAL) 单写者  │
                                               │ subjects / sessions  │
                                               │ sid_revocations      │
                                               │ seen_events          │
                                               └──────────────────────┘
```

*RP 进程之间不共享内存*，只共享数据库。因此所有一致性论证都落在
“哪些操作是同一个 SQLite 写事务”上。

---

## 3. 关键设计

### 3.1 一张票据 = 一个会话；同 sid 重试幂等

* `generation` 由 IdP 按 `(iss, sub)` 从 1 递增；`sid` 在 issuer 内永不复用。
* RP 用 `UNIQUE(iss, sid)` 存会话。同一票据重试返回**已有** `session_id`，
  `idempotent=true`；若该会话已被撤销，返回 `409 / state=revoked`，
  绝不重新激活。
* 同一个 `sid` 配**不同** `generation`/`sub` 是 issuer 违约或伪造，直接
  `409 sid_reuse_conflict`，且不触碰已存记录。

### 3.2 撤销靠“水位”，不靠接收时间

| 表 | 语义 |
|---|---|
| `subjects.cutoff_generation` | 每 `(iss, sub)` 的单调水位，只在 `max()` 上走 |
| `sid_revocations` | 每 `(iss, sid)` 的永久击杀，**允许 sid 从未登录过** |
| `sessions` | 本地会话：`generation` + 撤销来源 |

* 范围登出 `cutoff=K`：撤销 `generation <= 水位`，水位 `= max(旧水位, K)`。
  因此**迟到的低 cutoff 通知不会把水位拉回**，也不会漏掉中间代数。
* 单 sid 登出：先写击记录，再 `UPDATE sessions`；击记录先落盘，所以
  “登出先到、票据后到”时票据直接被拒（`sid_revoked`）。
* 判定撤销范围**只用票据里的 generation**；`received_at` 从不参与。

### 3.3 事件幂等与冲突

`seen_events(event_id PRIMARY KEY)`：

1. 事务 A：`INSERT ... applied=0`（或命中已有行）。同 id 不同
   **语义**内容（type/target/sub/sid/cutoff/iss）→ `409 event_conflict`，
   两份内容都不施加。
2. 事务 B：撤销 + `UPDATE ... applied=1` + 水位推进 + `revocation_epoch += 1`。
3. 只有 B 提交后才由 HTTP 层回 2xx；重复投递回
   `200 status=duplicate` 且不推进水位。

**两份内容**比较用的是 *语义摘要*（排除 `iat`/`exp`），所以通知方为重试而
重新签名同一事件不会被误判成冲突；而改目标/改 cutoff 一定会冲突。

### 3.4 鉴权缓存与“登出返回后不得放行”

* 缓存条目带 `epoch`。`epoch` 只在与撤销**同一个**事务里自增。
* 鉴权先读 `epoch`（单条 `SELECT`，读已提交），命中且 epoch 相同才放行。
* 登出必须先提交（epoch 才可见）**然后**才发响应 ⇒ 任何在登出响应**之后
  开始**的鉴权都会读到新 epoch，缓存必然失效。
* 缓存 TTL（默认 30s）另加墙钟过期检查，作为纵深防御。
* 即使缓存/行标记意外失配，鉴权仍会复核 `sid_revocations` 与水位，
  两者都是权威。

### 3.5 登录 vs 登出竞争

两者都在 `BEGIN IMMEDIATE` 内完成“检查 + 写入”：

* 登录先提交 ⇒ 会话行存在，登出的事务随后 `UPDATE` 撤销它；
* 登出先提交 ⇒ 登录在**同一事务内**看到水位/击记录，拒绝插入（`409`），
  或写入 `revoked=1` 的“出生即撤销”审计行，永不 `usable`。

不存在“水位已覆盖却 `usable` 的会话”。

### 3.6 两处真实进程终止

同步点是数据库里的 `hooks` 表（`DELETE ... RETURNING` 保证只被一个进程
消费）。`mode=die` 时进程在服务器内部调用 `os._exit(97)`：不执行
`finally`、不刷缓冲、不做解释器收尾。

| 阶段 | 位置 | 崩溃后磁盘状态 | 重发后的结果 |
|---|---|---|---|
| `logout.after_dedup` | 事务 A 已提交、事务 B 未开始 | `applied=0`，**未发响应** | 重新施加撤销，`applied=1` |
| `logout.after_commit` | 事务 B 已提交、响应未发出 | `applied=1`，状态已撤销 | 重复投递 ⇒ `duplicate` |
| `login.before_insert` | 登录写事务内 | 事务回滚，无半成品 | 同票据可再次登录 |

三种情况下都不会出现“通知已确认（2xx 已返回）但撤销未完成”：

* 未发响应 ⇒ 调用方无从确认 ⇒ 必然重发 ⇒ 磁盘上的 `applied=0` 触发重做；
* 已确认 ⇒ 必然已提交（2xx 在提交之后）⇒ 撤销已持久。

---

## 4. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/login` | `{"ticket": "<HS256>"}` → 会话或拒绝 |
| GET | `/v1/authcheck` | `Authorization: Bearer <session_id>` → 200/401 |
| POST | `/v1/logout/events` | `{"logout": "<HS256 event>"}` |
| GET | `/admin/state` | 全库快照（会话/水位/击记录/事件/钩子） |
| POST | `/admin/hooks` | 布置同步点：`{phase, port, mode, millis}` |
| GET | `/v1/status` | 本进程缓存统计 + 所见 epoch |
| GET | `/admin/health` | `{ok, pid, port}` |

IdP：`POST /idp/login`、`POST /idp/logout`、`POST /idp/adopt`、
`GET /idp/config`、`GET /idp/health`。

### 拒绝码（登录票据）

| 情况 | HTTP | `error` |
|---|---|---|
| 未知 issuer（在验签之前） | 401 | `unknown_issuer` |
| 签名不符 | 401 | `bad_signature` |
| header 不是精确的 `{"alg":"HS256","typ":"JWT"}`（含 `alg=none`/`HS512`/`jku`/`jwk`/`kid`） | 401 | `invalid_header` |
| header 或 payload 有重复 JSON 成员 | 401 | `invalid_json` |
| `aud` 不符 | 401 | `bad_audience` |
| `exp` 过期 / 非整数 | 401 | `expired` / `invalid_exp` |
| `generation` 非整数（含 bool、字符串） | 401 | `invalid_type` |
| 已撤销 sid / 被水位覆盖 | 409 | `session_revoked` |

密钥只来自预置配置；票据里的任何字段都不会被当作密钥地址。

---

## 5. 自动化测试

```bat
set PY=D:\CC_Codex_FeedBack\runtimes\cc005-csv-python312\python.exe
%PY% -m tests.run_all                 :: 全部
%PY% -m tests.run_all token crash     :: 名字含 token 或 crash 的
%PY% -m tests.run_all --list          :: 列出用例
```

每个用例都会新建临时目录、启动 1 个 IdP 子进程 + 2~4 个 RP 子进程，
**只用真实 HTTP** 交互，结束时清理。

覆盖点：

| 用例 | 覆盖 |
|---|---|
| `token-validation` | 未知 issuer、坏签名、`alg=none`/`HS512`、`jku`/`jwk`/`kid`、`aud`、过期、`generation` 类型 |
| `duplicate-json` | token 头/体重复成员、请求体重复成员 |
| `login-idempotency` | 同 sid 重试幂等、撤销后重试不复活、sid 复用拒绝 |
| `sid-logout-early` | 先登出后票据 |
| `range-watermark` | cutoff 单调、迟到低 cutoff、`<=cutoff` 全灭、`>cutoff` 放行 |
| `old-logout-new-login` | 旧登出晚于新登录到达 |
| `range-before-login` | 范围登出先于任何登录 |
| `cross-issuer` | 不同 issuer 同 sub/sid 完全隔离 |
| `event-dedup` | 重复投递、同 id 不同内容冲突且不施加 |
| `login-logout-race` | 登录写事务中途被阻塞时的竞争 |
| `auth-after-logout` / `cached-range-logout` | 四进程缓存预热后登出 |
| `crash-after-dedup` / `crash-after-commit` / `crash-mid-login` | 三处真实 `os._exit` + 重启 + 重发 |
| `concurrent-mixed` | 混合事件并发投递到 4 进程 |
| `permutation-matrix` | 同一组登录/登出：登录先行、事件先行、交错、逆序、全量重复、并发；逐轮对照独立参考状态机 |
| `auth-concurrency` | 登出 ack 之后的鉴权全部拒绝 |
| `restart-persistence` | 全进程重启后水位/击记录/去重持久 |
| `watermark-after-restart` | 重启不会让旧通知降低水位 |
| `arrival-time` | 范围由 generation 决定，与到达顺序无关 |
| `born-revoked` | 覆盖登录写入“出生即撤销”，永不 usable |

参考状态机在 `sso_local/state.py::ReferenceState`，只依赖
“水位取 max + sid 击杀集合 + 过期”，与 RP 的 SQL 完全独立。

---

## 6. 未完成项 / 明确的取舍

* **不是 OIDC**：无 discovery、无 JWKS 轮换、无授权码/刷新令牌/用户信息端点。
* **仅 HS256 单密钥**：没有密钥轮换或多密钥并存（`kid`/`jku` 被刻意拒绝）。
* **通知传输是同步 HTTP POST**：没有重试队列/指数退避；重试由调用方
  （测试或演示脚本）负责，这正是“重复/乱序投递”要演练的部分。
* **event_id 全局唯一**：跨 issuer 共用同一 id 会被判冲突；协议未约定
  命名空间前缀。
* **水位不回收**：`sid_revocations` 永久保留（测试规模下无妨）。
* **无 TLS / 无鉴权管理面**：`/admin/*` 只绑 `127.0.0.1`，无访问控制。
* **`cutoff_generation=0` 合法但撤销集合为空**；用于显式“清零”通知的测试。
* **登录票据 `exp` 同时限制会话寿命**：会话 `expires_at = min(exp, now+7d)`。
* **时延测试是概率性的**：`auth-concurrency` 以时间窗口采样；断言是
  “登出 ack 之后没有放行”，理论上有极小概率在 ack 前一瞬采样到 200，
  这时不计入 `after` 集合。

---

## 7. 文件布局

```
sso_local/
  strictjson.py   严 JSON：任何层级重复成员即拒
  tokens.py       固定 HS256 信封/验签/过期
  claims.py       票据与通知的语义校验
  config.py       预置 issuer/密钥/audience
  db.py           schema + BEGIN IMMEDIATE 工具
  store.py        唯一的状态变更与判定点
  state.py        参考状态机 / 导出 / 对比
  idp.py          身份提供方模拟器
  rp_server.py    HTTP 进程
  cli.py          命令行
tests/
  harness.py     子进程 + 真实 HTTP 的集群夹具
  run_all.py     自动化测试
  smoke.py       最小冒烟
scripts/
  demo.bat       一键演示
  run_tests.bat  一键测试
config/local.json
docs/PROTOCOL.md 协议细节与不变量证明
```
