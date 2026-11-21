# lan-scan

扫描局域网并识别设备/服务——只做被动指纹：TCP 连接 + 读取有限响应，不发任何凭据。

```
$ lan-scan
192.0.2.1       80    http          HTTP 200 · example-router
192.0.2.1       445   smb
192.0.2.10      5001  dangbei-tv    HTTP 200 · BaseHTTP/0.6 · 当贝市场
192.0.2.9       22    lab-device    unlocked · SSH-2.0-dropbear_2024.81
```

最后一行的 `lab-device` 来自其他工具安装的规则（见[规则](#规则)）：没有规则时它只是
`ssh`，规则把它变成一个可读的设备名。

## 识别类型

| kind | 判定方式 |
| --- | --- |
| `ssh` | 返回了 `SSH-` banner；它前面的一行（如果有）也会作为证据保留 |
| `http` | HTTP 服务，详情为 `状态码 · Server · <title>` |
| `dangbei-tv` | HTTP/5001 上是当贝市场的「远程推送」页 |
| `https` | TCP/443 开放（TLS 不做解析） |
| `smb` | TCP/445 开放 |
| `tcp` | 其他被探测端口有响应 |
| *自定义* | 规则匹配时，使用规则里的 `kind` |

## 参数

    --subnet=192.168.1     指定 /24 网段（可重复）；默认：本机所在 /24
    --include=IP           额外探测一个不在 /24 里的地址（可重复、逗号分隔），
                           例如 USB 网卡上的固定地址
    --ports=22,80,...      探测端口；默认 22,80,443,445,5001,8080，外加生效规则的端口
    --rules=FILE           追加规则文件（可重复）；`-` 从 stdin 读。
                           显式 --rules 会取代已安装的 rules.d
    --profile=NAME         只启用带该标签的规则（`all` = 全部；无标签的规则始终启用）
    --no-rules             忽略已安装规则，做纯通用扫描
    --filter=KIND          只输出 kind 包含 KIND 的结果
    --timeout=MS           单次探测连接+读取超时（默认 1500）
    --workers=N            并发数（默认 128）
    --json                 输出 JSON 数组
    --jsonl                每行一个 JSON 对象（字段相同）

网段一律裁剪为 /24。每个探测最多读 16 KB，不发送用户名、密码或密钥。

当规则要求 SSH 证据时，端口会先按 SSH 读（SSH 服务先说话）；HTTP 请求只在端口本身
是 HTTP 端口、或规则要求 HTTP 字段时发送。一个端口始终只复用一条 TCP 连接。

## 规则

规则是**纯数据，不是代码**：一个文件描述一类设备、它所在的端口/地址，以及探测必须
看到的被动证据。规则从 `~/.config/lan-scan/rules.d/*.conf`（或
`$XDG_CONFIG_HOME/lan-scan/rules.d`）读取，也可以用 `--rules FILE` 临时指定。

```ini
schema     = 1                  # 必填
kind       = lab-device         # 必填：输出/JSON 里的 kind
label      = Example lab device
profile    = lab                # 标签；没有标签的规则始终生效
ports      = 22
hosts      = 192.0.2.9          # 额外地址，不在 /24 网段里
match      = ssh.gate == unlocked
match      = ssh.banner ~ dropbear
confidence = definitive
```

* `match` 字段：`ssh.gate`、`ssh.banner`、`http.status`、`http.server`、
  `http.title`、`http.body`；运算符 `==`（完全相等，忽略大小写）和 `~`
  （包含，忽略大小写）。
* 所有 `match` 行必须同时成立。只有 `ports` 的规则匹配该端口上任何有响应的服务
  （这是候选，不是确证）。
* `confidence` 默认：有 `match` → `definitive`，只有端口 → `candidate`。
* 未知键、未知字段、缺少 `schema`/`kind` 都会报错——规则在加载和安装时都会校验。
  `http.body` 只用于匹配，不会打印。

指纹只说明「看起来像」，不说明「就是我的设备」：lan-scan 从不认证，凡是会发送凭据
的工具都必须保留自己的身份校验。

### 管理已安装规则

```sh
lan-scan rules install examples/lab-device.conf  # 校验后复制进 rules.d
lan-scan rules list                               # 名称、kind、端口、profile
lan-scan rules dir                                # rules.d 的位置
lan-scan rules remove lab-device                  # 按文件名删除
```

### 临时规则，不落盘

```sh
lan-scan --rules ./tv.conf --profile tv --jsonl
lan-scan --rules - --include 192.0.2.9 < lab-device.conf
```

## JSON

`--json` 输出数组，`--jsonl` 每行一个对象；两者字段相同：

```json
{"schema": 1, "ip": "192.0.2.9", "port": 22, "kind": "lab-device",
 "detail": "unlocked · SSH-2.0-dropbear_2024.81",
 "rule": "lab-device", "label": "Example lab device",
 "confidence": "definitive",
 "evidence": {"gate": "unlocked", "banner": "SSH-2.0-dropbear_2024.81"}}
```

`rule`、`label`、`confidence` 只在规则命中时出现。`evidence` 只包含对端真实给出的
字段（`gate`、`banner`、`status`、`server`、`title`），响应正文永远不会输出。schema
带版本号，调用方不需要猜格式。

## 构建

    make check      # fmt + clippy + 测试
    make release    # target/release/lan-scan
    make install    # cargo install --path .
