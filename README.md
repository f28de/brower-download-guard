# 下载守护 · Download Guard

一个适用于 **Microsoft Edge / Chrome**（Manifest V3）的下载安全插件：
**下载完成后自动计算 MD5 与 SHA-256，并借助 VirusTotal 等在线多引擎平台查毒**，无需在本机安装任何杀毒软件。

---

## 功能

| 能力 | 说明 |
| --- | --- |
| 自动查毒 | 监听 `downloads` 事件，下载完成即触发扫描，无需手动操作 |
| 双哈希 | 同一次读取中并行算出 **MD5** 与 **SHA-256**，一键复制 |
| 多引擎判定 | 通过 VirusTotal 查询该哈希的报告，展示 `N/M 个引擎报毒`、威胁家族名、具体检出引擎 |
| 网页送检 | 一键跳转 VirusTotal / Kaspersky OpenTIP / Hybrid Analysis（哈希直查）、VirScan / Jotti（自动复制哈希后手动上传） |
| 主动上传 | 文件未被收录时，可点击「上传查毒」把文件本体交给 VirusTotal 深度分析（需二次确认） |
| 威胁提醒 | 系统通知 + 工具栏角标（未读危险显示红色 `!`），可配置是否提醒安全文件 |
| 历史记录 | 保留最近 N 条扫描记录，支持按危险/安全筛选、导出 JSON |
| 隐私优先 | 默认**只把哈希值**发往 VirusTotal，文件内容不出本机 |

---

## 安装

### 方式一：加载已解压的扩展（开发 / 自用）

1. 打开 `edge://extensions/`（Chrome 为 `chrome://extensions/`）
2. 打开左下角「开发人员模式」
3. 点击「加载解压缩的扩展」，选择本目录 `download-guard/`
4. 首次安装会自动打开设置页

### 方式二：安装打包好的 zip

见 `dist/download-guard-1.1.0.zip`（校验值见 `dist/SHA256SUMS.txt`），解压后用上述方式加载；
或上传到 [Edge 加载项商店](https://partner.microsoft.com/dashboard/microsoftedge/overview) / Chrome 应用商店审核发布。

> ⚠️ **不要用 Windows 自带的「压缩为 ZIP」或 `Compress-Archive` 打包本扩展。**
> 它们会把子目录写成反斜杠（`lib\hash.js`），不符合 ZIP 规范；解包后 `lib/` 目录为空，
> `background.js` 的 `import './lib/hash.js'` 会 404，**整个扩展无法启动**。
> 请使用下面的 `node _dev/package.mjs`。


---

## 首次配置（两步）

### ① 授权读取下载来源

浏览器扩展在沙箱中运行，**无法直接读取你硬盘上的文件**。因此本插件会在下载完成后，
以只读方式重新拉取一次该下载链接，边读边算哈希（不落盘、不缓存、读完即丢）。

在设置页点击「授权读取下载来源」即可。该权限是**可选项（optional_host_permissions）**，
只在你点击时才会申请，安装时不会索取。

### ② 填写 VirusTotal API Key

1. 注册 [VirusTotal](https://www.virustotal.com/) 账号
2. 在 [API Key 页面](https://www.virustotal.com/gui/my-apikey) 复制 Key
3. 粘贴到设置页，点「验证 Key」

> 免费额度：**4 次/分钟、500 次/天、15.5K 次/月**。插件内置请求排队与限速，不会把额度打爆。
> 免费 API 仅限非商业用途，商业场景请遵守 VirusTotal 服务条款。

不填 Key 也可以使用：插件仍会计算并展示 MD5 / SHA-256，只是不会自动查毒。

---

## 工作原理

```
downloads.onChanged(state=complete)
        │
        ├─ 记录文件名 / 大小 / 来源 URL / MIME
        │
        ├─ 重新以流式方式读取下载链接 ──► 增量计算 MD5 + SHA-256（内存占用恒定）
        │
        ├─ GET https://www.virustotal.com/api/v3/files/{sha256}
        │      └─ 200 → 解析 last_analysis_stats / last_analysis_results
        │      └─ 404 → 未收录，提示可上传或手动送检
        │
        └─ 写入记录 → 通知 + 角标 + 弹窗列表
```

### 为什么是「重新拉取」而不是「读取本地文件」？

Manifest V3 的扩展无法访问任意本地路径（`chrome.downloads` 只给元数据，不给文件内容）。
要实现「不装本地软件也能拿到哈希」，只有两条路：

1. 打包一个 Native Messaging 宿主程序 —— 但这需要用户额外安装可执行文件，违背「无需下载软件」的初衷；
2. 重新读取下载链接 —— 本插件采用的方案，纯扩展实现，零额外安装。

代价是会多消耗一次下载流量。为此插件提供了**大小上限**（默认 256 MB，可调 64 MB ~ 1 GB），
超过上限的文件会跳过自动扫描并在界面中说明原因。

### 哈希为什么可能"不准"？

如果下载需要登录、链接是一次性的、或服务器对二次请求返回了错误页，
重新读到的内容就不是原文件，算出的哈希自然不对。
插件会比对**读取到的字节数**与浏览器记录的 `fileSize`，不一致时在卡片上给出橙色警示，
提示改用「上传查毒」或手动送检。这是刻意设计的安全兜底，避免给出错误结论。

---

## 隐私说明

- 不收集、不上传任何遥测数据；没有后端服务器。
- 默认只向 `www.virustotal.com` 发送 **SHA-256 哈希**，文件内容不出本机。
- 只有在用户点击「上传查毒」并确认后，文件本体才会被上传到 VirusTotal。
- 所有扫描记录仅保存在 `chrome.storage.local`（本机浏览器存储），可随时导出或清空。
- API Key 同样只存在本机，不会同步到任何地方。

详见 [PRIVACY.md](PRIVACY.md)。

---

## 安全设计说明

| 关切 | 实际做法 |
| --- | --- |
| **凭证泄露** | **默认不携带任何 Cookie**（`credentials: 'omit'`）。只有你在某条记录上点击「携带登录信息重试」并确认后，该次请求才使用 `include`，且只针对这一条记录。 |
| **重定向劫持** | 带凭证的请求使用 `redirect: 'error'`——**任何重定向都会立即中止**，Cookie 不可能跨跳转边界。不带凭证的请求允许跟随（没有凭证可泄露）。此外，浏览器给出的 `finalUrl` 已是重定向后的地址，扩展直接请求最终地址，正常路径下根本不产生跳转。 |
| **任意站点访问** | 请求前做地址准入检查：仅允许 `http(s)`；拒绝 URL 内嵌账号密码；**默认拒绝本机/内网/链路本地地址**（防 SSRF，含云元数据地址 169.254.169.254）；支持用户自定义主机排除列表。 |
| **API Key 是否外泄** | 只存 `chrome.storage.local`，仅作为 `x-apikey` 头发给 `www.virustotal.com`；无服务器、无遥测、不参与账号同步。 |
| **跨域跳转的内容可信吗** | 记录上会标记「经过跨域跳转」并在界面提示；配合文件大小比对，不一致时给出橙色警示。 |
| **文件名是否可用于路径遍历** | 不会。扩展**没有任何文件系统写入操作**，文件名仅作字符串展示（`textContent` 渲染）；并会剥离控制字符与双向覆写符（U+202E 可把 `.exe` 显示成 `.txt`）。 |
| **错误信息是否泄露细节** | 仅向本机用户展示可读原因（如 `HTTP 403`），不含堆栈或响应头；上游返回文本截断到 120 字符。 |
| **限速是否会被击穿** | SW 单线程 + Promise 链串行化；限速状态持久化在 `chrome.storage.session`，重启不重置；命中 429 后进入 60 秒冷却。 |
| **权限是否最小化** | 必需权限仅 `downloads` / `storage` / `notifications` + `https://www.virustotal.com/*`；宽泛的 `http(s)://*/*` 放在 `optional_host_permissions`，安装时不索取，可随时撤销。 |

### 关于「为什么不直接删掉 credentials / 加 URL 白名单」

- **删掉 `credentials`**：已改为默认 `omit`，效果等同于"删掉"。但完全移除会让网盘、企业内网等需要登录态的下载源永远算不出哈希，所以保留为**单条记录、显式确认**的提权入口。
- **URL 白名单**：下载源是任意站点，硬编码白名单等于废掉核心功能。因此改为**准入策略**（协议 / 内嵌凭证 / 内网地址 / 用户排除列表），这是能落地且有效的形态。
- **`redirect: 'manual'`**：在 Service Worker 中会得到 `opaqueredirect` 响应（status 0、无 `Location` 头），**无法据此手动跟随**，所以改用「带凭证不跟随 + 直接请求 finalUrl」的组合。

--- | --- |
| **API Key 是否会被采集/外泄** | Key 只存 `chrome.storage.local`，仅作为 `x-apikey` 头发给 `www.virustotal.com`；无服务器、无遥测、不参与账号同步。 |
| **重新拉取时会不会泄露 Cookie** | 会携带**该下载源本身**的 Cookie（网盘/内网下载需要登录态），但不带 `Referer`；Cookie 不会发给其他域名，也不被读取或保存。可在设置中关闭。 |
| **下载链接被重定向到恶意站点** | `redirect: 'follow'` 遵循浏览器标准的逐跳凭证规则，与你在地址栏直接下载时的行为一致；扩展不读取响应内容以外的任何信息，也没有把响应发往别处的代码路径。 |
| **文件名是否可用于路径遍历** | 不会。扩展**没有任何文件系统写入操作**，文件名仅作字符串展示（`textContent` 渲染，无 HTML 注入）；另外会剥离控制字符与双向覆写符（如 U+202E，可把 `.exe` 显示成 `.txt`）。 |
| **错误信息是否泄露服务器细节** | 仅向**本机用户**展示可读原因（如 `HTTP 403`），不含堆栈或响应头；上游返回的文本会被截断到 120 字符。 |
| **限速是否会被并发击穿** | Service Worker 单线程 + Promise 链串行化；限速状态持久化在 `chrome.storage.session`，SW 被回收重启后不会重置；命中 429 后自动进入 60 秒冷却。 |
| **权限是否最小化** | 必需权限仅 `downloads` / `storage` / `notifications` + `https://www.virustotal.com/*`；宽泛的 `http(s)://*/*` 放在 `optional_host_permissions`，安装时不索取，可随时撤销。 |


---

## 已知限制

| 限制 | 原因 / 说明 |
| --- | --- |
| 仅支持 `http(s)` 直链下载 | `blob:` / `data:` / `file:` 下载无法二次读取，会提示"无法读取文件内容" |
| 需要重新消耗一次下载流量 | 见上文「工作原理」 |
| 大文件默认跳过 | 默认上限 256 MB，可在设置中调整 |
| 依赖 VirusTotal 免费额度 | 内置 15 秒/次限速 + 429 冷却 60 秒；批量下载时会排队，界面显示"查询中" |
| 单次上传上限 32 MB | VirusTotal 直传接口限制，超出需到网站手动上传 |
| 结果仅供参考 | 未检出不等于绝对安全，不能替代专业杀毒软件 |

---

## 目录结构

```
download-guard/
├── manifest.json          # MV3 清单：最小权限 + CSP + 可选主机权限
├── background.js          # Service Worker：下载监听、哈希、VT 查询、通知、角标
├── popup.html/css/js      # 弹窗：记录列表、哈希复制、站点跳转
├── options.html/css/js    # 设置页：授权、API Key、扫描策略、数据管理
├── lib/
│   ├── hash.js            # 纯 JS 增量 MD5 / SHA-256（流式，内存恒定）
│   ├── vt.js              # VirusTotal API v3 客户端
│   ├── sites.js           # 在线查毒站点链接规则
│   ├── store.js           # 记录持久化（带并发锁）
│   ├── settings.js        # 设置项默认值与读写
│   └── util.js            # 格式化 / 剪贴板等工具
└── icons/                 # 16 / 32 / 48 / 128 PNG
```

---

## 开发与测试

工程校验与测试脚本位于上级目录 `_dev/`（不随扩展打包）：

```bash
node _dev/validate.mjs         # 静态校验：manifest、ESM 语法、CSP、远程代码、import 路径、权限审查、发布包
node _dev/package.mjs          # 构建发布包（白名单 + 规范 ZIP + SHA-256 校验值）
node _dev/test-hash.mjs        # 哈希算法对拍 Node crypto（296 项，含边界长度与随机分块）
node _dev/test-util.mjs        # 纯函数单测（38 项，含文件名净化 / U+202E 双向覆写防护）
node _dev/test-hostpolicy.mjs   # 地址准入策略（60 项：内网识别 / 协议 / 内嵌凭证 / 排除列表）
node _dev/test-vt.mjs          # VT 客户端（39 项，模拟 fetch，不消耗真实额度）
node _dev/test-integration.mjs # 真实 Edge 端到端（48 项断言：下载 → 哈希 → 查毒 → 通知 → 角标 → 凭证/重定向策略 → 内网拦截 → 截图）
node _dev/make-icons.mjs       # 重新生成图标
```

### 发布前必做：验证「打包产物」本身能跑

源码能跑 ≠ 打包产物能跑。务必先解包、再对解包目录跑一遍端到端测试：

```bash
node _dev/package.mjs
# 解压 dist/download-guard-x.y.z.zip 到任意目录，然后：
DG_EXT_SRC=/path/to/解压目录 node _dev/test-integration.mjs
```

当前状态：**静态校验 0 错误 0 警告，单测 433 项、端到端 48 项全部通过（源码与解包产物均已验证）。**

`test-integration.mjs` 会启动一个无头 Edge 实例，加载插件、触发真实下载、
并在 Service Worker 中拦截 VirusTotal 请求返回模拟响应，最终输出 `_dev/shots/*.png` 界面截图。

---

## 版本

**1.1.0** — 凭证与网络访问策略重构：默认不携带 Cookie（改为单条记录显式提权）、带凭证请求禁止跟随重定向、
新增地址准入策略（拒绝内网/本机地址，可配置主机排除列表）、跨源跳转标记、凭据模式可双向切换。

**1.0.1** — 安全加固：限速状态跨 Service Worker 重启持久化、429 冷却、文件名净化（防 U+202E 伪装）、
`no-referrer`、权限收窄为 http(s)、文档补充 API Key 存储说明。

**1.0.0** — 首个正式版本。

## 免责声明

本插件为辅助判断工具，查毒结果来自 VirusTotal 聚合的第三方引擎，可能存在误报与漏报。
请勿将其作为唯一的安全依据。
