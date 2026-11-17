# GPT 账号额度管理助手

基于 PyQt5 构建的 Windows 桌面工具，用于本地管理多个 GPT 账号凭据与额度状态，支持 5h 额度倒计时自动恢复、周额度倒计时恢复、长文本智能识别导入、昼夜主题切换以及周额度即将刷新系统通知。

## 核心功能

- **账号与凭据管理**：支持添加、编辑、删除、搜索与筛选账号（名称、邮箱、密码掩码/显示/复制、2FA 初始验证码或 Base32 实时 6 位 TOTP 计算）。
- **智能文本识别**：支持单条智能填充与批量文本识别导入，可从包含声明、链接、emoji 的混合文本中提取 `邮箱----密码----2FA`。
- **5h 额度自动恢复**：
  - 点击 **「开始使用」** 立即开启 5 小时倒计时，或当 5h 额度设为 `0` 时自动触发 5 小时倒计时。
  - 倒计时结束（含离线期间到期补齐）后自动恢复为 `100`。
- **周额度倒计时与即将刷新提醒**：
  - 支持设置周额度剩余重置时间（天/时/分），到期自动恢复为 `100`。
  - 支持配置周额度预警阈值（默认剩余 `≥ 20%` 且剩余时间 `< 24 小时`）弹出 Windows 原生桌面通知，并支持通过 Windows 计划任务在未打开软件界面时每小时后台静默检测提醒。
- **昼夜双主题与本地持久化**：支持日间（白）/ 夜间（黑）主题切换；账号数据原子写入 `data/accounts.json`，配置写入 `data/settings.json`，事件日志写入 `logs/events.jsonl`。

## 本地运行与构建

```bash
pip install -r requirements.txt

# 运行界面
python main.py

# 运行测试
python -m unittest discover -s tests -v

# 编译单文件 EXE
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "GPT管理助手" --icon "assets/app.ico" --add-data "assets/app.ico;assets" --exclude-module PyQtWebEngine --exclude-module nltk --exclude-module matplotlib --exclude-module numpy --exclude-module pandas --exclude-module scipy --exclude-module IPython --exclude-module jupyter main.py
```
