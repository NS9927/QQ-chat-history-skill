# qq-chat-decrypt

解密并读取 **本机 QQ NT（Windows）聊天数据库** —— 抓密钥、剥文件头、查消息表、解析 Protobuf 正文。

同时是一个 [DeepSeek Harness](https://github.com/deepseek-ai) skill（`SKILL.md` + `scripts/`），
也可以当普通命令行工具单独用。

---

## ⚠️ 免责声明（先读）

- 本工具**只应解密你自己的账号、你自己设备上的本地数据**。
- 未经他人同意读取、传播他人的聊天记录可能违反法律与平台规则。
- 作者不对任何滥用行为负责。
- 仓库内不含任何真实密钥或真实账号信息，示例数据均为虚构。

---

## 它能做什么

| 能力 | 说明 |
|---|---|
| 抓数据库密钥 | Frida hook `nt_sqlite3_key_v2`，从运行中的 QQ 进程内存里读 16 字节密钥 |
| 解密 | 剥掉 NTQQ 的 1024 字节自定义头，用 SQLCipher 参数打开 |
| 查询导出 | 按私聊对象 / 群号 / 发送者 / 日期筛选，导出 JSONL |
| 解析正文 | 手写 Protobuf 解析器处理 `40800` 消息体，无需 protobuf 依赖 |

---

## 前置条件

- **QQ NT**（新版 Windows QQ），装在 `C:\Program Files\Tencent\QQNT`
- **目标账号必须处于登录状态** —— 数据库密钥只存在于 QQ 进程内存里
- Python 3.10+

### 装依赖：用专用 venv

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install frida sqlcipher3-wheels
```

**别用系统 Python 或任何会被重置的环境** —— 实测 DSH 的 bundled runtime 更新后会丢包。
两个包都有 cp314 预编译轮子，不需要编译。实测组合：Python 3.14.7 + frida 17.24.3 + sqlcipher3-wheels 0.5.7。

---

## 三步用法

### 1. 定位函数地址

```bash
python scripts/find_key_rva.py "C:/Program Files/Tencent/QQNT/versions/<版本>/resources/app/wrapper.node"
```

原理：在 `wrapper.node` 里搜字符串 `nt_sqlite3_key_v2: db=%p zDb=%s`，找引用它的 LEA 指令，
再用 `.pdata` 异常表反查所属函数起始 RVA。

### 2. 抓密钥

```bash
python scripts/hook_key.py --rva <上一步算出来的 RVA> --seconds 600
```

Frida 附加到所有 `QQ.exe`，在函数入口读密钥指针。命中示例（**示例值，非真实密钥**）：

```text
HIT pid=18820 zdb=main n=16 key='0123456789abcdef'
```

- `n=16` = 聊天库密钥；`n=20` = `login.db` 硬编码密钥（不是目标）
- 密钥是**账号级固定**的，抓到一次就能开该账号所有 `nt_*` 库；**QQ 升级后密钥不变**
- 满屏 `refused to load frida-agent` **是正常的**（16 个进程只有 2 个能注入），看到 `injected into pid=...` 就说明有戏
- **要等 2~5 分钟**（实测 3 分 37 秒）。QQ 已登录时后台任务会周期性重开库，hook 就那时抓到
- 想更快：点开几个聊天窗口 / 消息管理器，触发开库

### 3. 查询导出

```bash
python scripts/qq_query.py \
  --db "C:/Users/<你>/Documents/Tencent Files/<QQ号>/nt_qq/nt_db/nt_msg.db" \
  --key '0123456789abcdef' \
  --out out.jsonl \
  --peer 123456789
```

筛选参数：

| 参数 | 作用 |
|---|---|
| `--peer <QQ>` | 私聊对象 |
| `--group <群号>` | 群聊 |
| `--sender <QQ>` | 只看某个人发的 |
| `--day 2026-10-04` | 按日期（UTC+8） |
| `--since` / `--until` | Unix 秒区间 |
| `--sent-only` | 只要本人发出的 |
| `--limit N` | 总共最多 N 条 |
| `--retries N` | 撕裂页重试次数（默认 3） |

输出每行一条：`{ts, unix, table, msg_id, direction, sender, uid, peer, session, card, nick, text, segments}`

---

## ⚠️ 最容易卡住的地方

**1. RVA 每个 QQ 版本都不一样。** 下面的数字只是历史记录，**必须用 `find_key_rva.py` 现算**：

| QQ 版本 | RVA |
|---|---|
| 9.9.35-52892 | `0x21b8c80`（已失效） |
| 9.9.36-53644 | `0x21ebe20` |

先 `ls "C:/Program Files/Tencent/QQNT/versions"` 看当前版本，再跑脚本。

**2. Hook 要等，而且报错是假的。** 见上一步的说明。

---

## 作为 DSH skill 使用

```bash
git clone <本仓库> ~/.dsh/skills/qq-chat-decrypt
```

DSH 会自动扫描 `~/.dsh/skills` 下的目录，读取 `SKILL.md` 的 frontmatter 注册到 skill 目录。

---

## 踩过的坑（SKILL.md 有完整表）

| 现象 | 原因 |
|---|---|
| `file is not a database` | 忘了剥 1024 字节头 |
| `hmac check failed for pgno=1` | 密钥错，或 PRAGMA 顺序不对 |
| 查询恒返回 0 行 | **数字列名没加双引号**（`WHERE "40030"=` 而不是 `WHERE 40030=`） |
| `database disk image is malformed` | 活跃库撕裂页，重新快照 |
| 抓到 `n=20` 的 key | 那是 `login.db` 的，继续等 16 字节的 |

---

## 结构

```text
QQ-chat-history-skill/
├── SKILL.md                  Agent 指令（流程、坑表、字段速查）
├── scripts/
│   ├── find_key_rva.py       定位密钥函数 RVA
│   ├── hook_key.py           Frida 抓密钥
│   └── qq_query.py           剥头 + 查询 + 解析 40800 + 导出
├── README.md                 本文件
└── LICENSE
```

---

## License

MIT
