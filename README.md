# AI 多平台账号双窗额度与防关联调度控制台 (v2.0)

基于 PyQt5 构建的 Windows 桌面工具，统一纳管 **ChatGPT / Claude / Codex / Custom** 多账号凭据、5h 滚动窗口与周限额倒计时、防关联独立浏览器隔离启动、离线原生 OCR 额度回填、外购质保防损账本与端到端加密云同步。

## 功能特性

- **系统级密文存储与端到端云同步 (`M1`)**：
  - 本地 `data/accounts.json` 与 `data/settings.json` 中的登录密码、2FA 种子密钥及 WebDAV 密码全部经由 **Windows DPAPI (`CryptProtectData`)** 绑定当前系统账户透明加密落盘；自动兼容旧版 v1 明文文件并静默升级。
  - 支持导出/导入跨设备 **PBKDF2-HMAC-SHA256 (600,000 轮) + AES-256-GCM** 加密备份包，支持坚果云 / Nextcloud 等 **WebDAV 端到端加密同步** 与基于 `updated_at` 的 Last-Write-Wins (LWW) 多端合并。
- **系统 Codex 登录监测与免密一键自动录入纳管 (`M7 - 零手动录入`)**：
  - 软件启动与运行过程中通过 `QFileSystemWatcher` 毫秒级监测宿主机 `~/.codex/auth.json` 授权变化。
  - 自动无损解析 JWT Claims，秒级提取账号邮箱、用户名昵称、会员等级（Plus / Team / Pro / Free）及官方订阅到期时间戳。
  - **开机自动感知**：发现未纳管 Codex 账号时自动置顶高亮横幅，支持「一键自动纳管」，自动加密归档快照，无需手动填写任何邮箱或密码。
  - **官方登录录入**：提供「⚡ 官方登录新号」向导，一键调起浏览器官方 OAuth 页面，用户登录完成后自动截获全部账号元数据并原子入库。
- **双时间窗防作废智能派号引擎 (`M2 - EEQF`)**：
  - 综合周剩余额度、周刷新剩余时间与账号健康权重计算防作废紧急度评分，一键选出当前最紧急可用账号，自动启动 5h 倒计时并装载上号吐码队列（快捷键 `Ctrl+Shift+D`）。
- **Chromium 独立目录防关联启动 + 三段式吐码队列 + TOTP 临期防失效 (`M3`)**：
  - 调用宿主机 Edge / Chrome / Brave 为每个账号创建独立 `--user-data-dir` 与独立 `--proxy-server`（严格拦截命令行参数注入），物理隔离多号 Cookie 与出口 IP。
  - 三段式顺序吐码（`1.邮箱 -> 2.密码 -> 3.动态2FA`）：当 6 位 TOTP 剩余有效期 `<= 3s` 时自动顺延等待新 30 秒周期验证码，并在粘贴后按设定秒数执行剪贴板阅后即焚（自动校验剪贴板内容防止误删用户文本）。
- **零网络请求离线 OCR 校准 + 本地 Codex CLI 凭证热切换 (`M4`)**：
  - 调用 Windows 10/11 内置离线 `Windows.Media.Ocr` 引擎（支持全屏框选截图、系统剪贴板截图 `Win+Shift+S`、本地图片），自动解析中/英文“剩余%”与“已用%（自动换算 `100 - used`）”及周重置倒计时。
  - 支持捕获本地 `~/.codex/auth.json` 加密快照并一键原子热切换终端 Codex CLI 登录账号。
- **外购质保防损账本、渠道 ROI 看板与置顶微型胶囊窗 (`M5 & M6`)**：
  - 支持追踪渠道标签、采购单价、质保倒计时与健康状态（`正常可用` / `疑似降智` / `待接码` / `已封禁`）；支持 Windows 计划任务离线每小时静默巡检周额度与质保临期提醒，一键生成标准化异常账号售后凭条。
  - 内置 `356 × 106 px` 无边框置顶微型胶囊悬浮窗（Mini HUD），支持拖拽常驻、一键派号、步进吐码与框选 OCR。

## 本地运行与构建

```powershell
pip install -r requirements.txt

# 运行图形界面
python main.py

# 运行全量单元测试与对抗测试套件
python -m unittest discover -s tests -v

# 编译单文件独立 EXE
python -m PyInstaller --clean --noconfirm "GPT管理助手.spec"
```
