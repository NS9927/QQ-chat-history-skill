---
name: qq-chat-decrypt
description: Decrypt and read local QQ NT (Windows) chat databases. Extracts the SQLCipher key from the running QQ process with a Frida hook, strips the NTQQ 1024-byte header, queries c2c/group message tables, and parses the 40800 protobuf message body. Use when the user asks to analyze, export, summarize, or build a style profile from their own local QQ chat history.
---

# QQ NT 聊天记录解密与读取（Windows）

## 适用场景

用户要求分析、导出、汇总本机 QQ 聊天记录（例如「提炼某人的说话风格」「今天群里聊了什么」）时使用。

**不适用**：移动端 QQ、TIM 旧架构、PCQQ 非 NT 架构；也不要在没有明确授权时读取他人账号数据。全程**只读**，绝不改写原始数据库。

## 前置条件

- QQ NT（新版 Windows QQ，装在 `C:\Program Files\Tencent\QQNT`）
- **目标账号必须处于登录状态**——数据库密钥只存在于 QQ 进程内存里
- Python 3.10+，装 `frida` 和 `sqlcipher3-wheels`

### ⚠️ 用专用 venv，别依赖系统 / bundled Python

DSH 自带的 bundled runtime **会被更新重置**，装好的包会凭空消失（实测：隔天 `import frida` 就报 `ModuleNotFoundError`）。所以固定用项目内 venv：

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install frida sqlcipher3-wheels
```

之后所有命令都用 `.venv\Scripts\python` 跑。

实测可用组合（2026-10）：**Python 3.14.7 + frida 17.24.3 + sqlcipher3-wheels 0.5.7**。
两者都有 cp314 预编译轮子，**不需要编译**。

> ⚠️ **frida 的轮子有 58 MB，国内直连可能只有 100~200 kB/s（实测 126 kB/s，耗时 13 分半），看起来像卡死但其实在下载。**
> 别中途掐掉。想快就换源：
> ```powershell
> .venv\Scripts\python -m pip install frida sqlcipher3-wheels -i https://pypi.tuna.tsinghua.edu.cn/simple
> ```

## 0. 总体流程

1. 找到目标账号的 nt_msg.db
2. 用 Frida hook `nt_sqlite3_key_v2`，抓到 16 字节密钥
3. 剥掉文件头 1024 字节，用 SQLCipher 参数打开
4. 查询 `c2c_msg_table` / `group_msg_table`
5. 解析 `40800` Protobuf 得到正文
6. 导出 JSONL，用完删掉临时副本

脚本都在本 skill 的 scripts/ 目录。

## 1. 定位数据目录

每个登录过的 QQ 号一个文件夹：

    C:\Users\<用户名>\Documents\Tencent Files\<QQ号>\nt_qq\nt_db\nt_msg.db

判断**当前登录**的是哪个号：看 `nt_msg.db` 和 `nt_msg.db-wal` 的修改时间，一直在变的就是活动账号。多账号时其他人的库是旧快照，**密钥也不通用**。

## 2. 取数据库密钥

### 2.1 找到函数地址

    python scripts/find_key_rva.py "C:\Program Files\Tencent\QQNT\versions\<版本>\resources\app\wrapper.node"

原理：在 wrapper.node 里搜字符串 `nt_sqlite3_key_v2: db=%p zDb=%s`，找引用它的 LEA 指令，再用 `.pdata` 异常表反查所属函数起始 RVA。入口约定 `rcx=db, rdx=zDbName, r8=pKey, r9d=nKey`。

> ⚠️ **RVA 每个 QQ 版本都不一样，必须现算。文档里的数字只是历史记录，不要直接抄。**
>
> | QQ 版本 | `versions\` 下的目录 | 函数 RVA |
> |---|---|---|
> | 9.9.35-52892 | `9.9.35-52892` | `0x21b8c80`（**已失效**） |
> | 9.9.36-53644 | `9.9.36-53644` | `0x21ebe20` |
>
> 先看当前版本：`ls "C:\Program Files\Tencent\QQNT\versions"`，再跑脚本。QQ 一升级 RVA 就变，这是最常见的翻车点。

### 2.2 Hook 抓密钥

    python scripts/hook_key.py --rva 0x21ebe20 --seconds 600

Frida 会附加到所有 `QQ.exe` 进程，在函数入口读 `args[2]`（pKey 指针）和 `args[3]`（nKey）。命中示例：

    HIT pid=21576 zdb=main n=16 key='0123456789abcdef'

**注意（这几条是隔壁会话卡了半天的原因，逐条看完）：**

- **n=16** 是聊天库密钥；**n=20** 是 `login.db`（全客户端硬编码，不是我们要的）
- **大部分 `QQ.exe` 子进程会 `attach failed`，这是正常的。** 实测 16 个进程只有 2 个注入成功——只要看到 `injected into pid=...` 就说明有戏，**别被满屏红字吓到，那不是失败**
- **要等 2~5 分钟，别以为没戏就掐了。** 实测 **3 分 37 秒**才命中。QQ 即使已经登录，后台任务也会周期性重开数据库，hook 就是那时候抓到的
- 想让它更快：在 QQ 里点开几个聊天窗口 / 消息管理器，触发新的开库
- 等太久还不命中：把 `--seconds` 调大（默认 300，建议 600 以上），或检查 RVA 是不是跟当前 QQ 版本对得上
- 密钥是**账号级固定**的，抓到一次就能开该账号所有 `nt_*` 库（`group_info.db`、`misc.db` 等同理）
- **QQ 升级后密钥不变**（实测 9.9.35 → 9.9.36 后旧密钥依旧能解密），但**函数 RVA 会变**
- 抓到的密钥**先用第 3 步验证**，不要直接信

## 3. 解密 / 打开数据库

NTQQ 的库是 **SQLCipher**，文件前面有 **1024 字节自定义头**（以 `SQLite header 3` 开头，不是标准 SQLite 魔数）。

参数（顺序不能错）：

    PRAGMA cipher_page_size = 4096;          -- 必须在 key 之前
    PRAGMA key = '<16位密钥>';
    PRAGMA kdf_iter = 4000;
    PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
    PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;

验证：`SELECT count(*) FROM sqlite_master` 能返回行数就算成功（失败通常报 `hmac check failed for pgno=1`）。

**别改原库**：复制一份、剥头、在副本上查。11GB 的库复制约 15 秒。

### 活跃库的坑

QQ 正在写这个文件，复制可能产生**撕裂页**，表现为：

- `database disk image is malformed`
- `max(rowid)` 能过，但全表扫描崩

对策一：直接用 `scripts/qq_query.py`，它已经把「快照→查询→失败重试」包好了，默认重试 3 次（`--retries`）。

对策二：手工流程——复制后先跑一次全表扫描校验（例如 `SELECT count(*) FROM group_msg_table WHERE "40033"=<任意QQ>`），失败就重新复制，通常 1–2 次能过。

## 4. 查询消息

两张主表：`c2c_msg_table`（私聊）、`group_msg_table`（群聊），结构一致。

**最重要的坑：列名是数字，SQL 里必须加双引号。**

    -- 错：40030 被当成整数常量，恒不等于 123456789，返回 0 行
    SELECT count(*) FROM c2c_msg_table WHERE 40030=123456789;
    -- 对：
    SELECT count(*) FROM c2c_msg_table WHERE "40030"=123456789;

常用字段：

| 列 | 含义 |
|---|---|
| 40001 | 消息 ID（主键） |
| 40013 | 方向：0 收到，1/2 本人发出，3 系统 |
| 40020 / 40033 | 发送者 NT UID / QQ 号 |
| 40021 / 40030 | 会话对象：私聊对方 QQ / 群号 |
| 40027 | 本地会话键（私聊=对方，群=群号） |
| 40050 | Unix 秒时间戳 |
| 40058 | UTC+8 当天零点时间戳 |
| 40090 / 40093 | 发送者群名片 / 昵称 |
| 40011 / 45002 | 外层消息类型 / 内容子类型 |
| 40800 | 消息体（Protobuf BLOB） |

**rowid 是随机 64 位值，不随时间递增**，不要按 rowid 翻页找最近消息；用 `40050` 过滤。

## 5. 解析 40800

    MsgBody { repeated MsgContent content = 40800; }
    MsgContent {
      45001 段级 ID
      45002 内容类型
      45101 文本正文（UTF-8）
      47602 表情外显文字
      45402 文件名
      80900 商城表情文字
      47710 引用块（嵌套，别把里面的文本当本体）
    }

45002 取值：1 文本、2 图片、3 文件、4 语音、5 视频、6 QQ表情、7 引用、8 灰条、9 红包、10 Ark 卡片、11 商城表情、14 Markdown、21 通话。

## 6. 导出与善后

    python scripts/qq_query.py \
      --db "C:\Users\...\nt_msg.db" \
      --key '<16位密钥>' \
      --out ./qq_messages.jsonl \
      --peer 123456789

筛选参数：

| 参数 | 作用 |
|---|---|
| `--peer <QQ>` | 私聊对象（c2c_msg_table） |
| `--group <群号>` | 群聊（group_msg_table） |
| `--sender <QQ>` | 只看某个人发的 |
| `--day 2026-10-04` | 按日期（UTC+8） |
| `--since / --until` | 按 Unix 秒区间 |
| `--sent-only` | 只要本人发出的（40013 in 1,2） |
| `--limit N` | 总共最多 N 条（跨表累计，0=不限） |
| `--retries N` | 撕裂页重试次数，默认 3 |

不给 `--peer` / `--group` 时两张表都查。

输出每行一条：`{ts, direction, sender, peer, text, segments}`。

**善后（必做）**：

- 删除剥头后的中间副本（可能有数 GB）
- 不要把密钥、QQ 号、群号、真实昵称写进任何交付物
- 涉及真人时只做风格/话题统计，不做定位性描述

## 7. 排查表

| 现象 | 原因 / 处理 |
|---|---|
| file is not a database | 忘了剥 1024 字节头 |
| hmac check failed for pgno=1 | 密钥错，或 PRAGMA 顺序/参数不对 |
| 查询恒返回 0 行 | 数字列名没加双引号 |
| database disk image is malformed | 复制到撕裂页，重新快照 |
| 抓到 n=20 的 key | 那是 login.db 的，继续等 16 字节的 |
| 控制台中文乱码 | 设 PYTHONIOENCODING=utf-8 |
| Frida 满屏 `refused to load frida-agent` | **正常**。多数子进程拒绝注入，只要有 1~2 个 `injected into` 就行，不用重试 |
| 一直等不到 `HIT` | ① 先等够 2~5 分钟 ② 检查 RVA 是否对应当前 QQ 版本 ③ 点开几个聊天窗口触发开库 |
| `ModuleNotFoundError: No module named 'frida'` | 用的是被重置的 bundled Python；改用项目内 `.venv` 并重装依赖 |
| 查询能跑但结果全是乱码 | 设 `PYTHONIOENCODING=utf-8` |
