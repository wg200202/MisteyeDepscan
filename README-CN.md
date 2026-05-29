# MistEye DepScan

[中文版](README-CN.md) | [English](README.md)

面向 [MistEye](https://app.misteye.io/api-docs) 威胁情报 API 的轻量 CLI，用于扫描项目依赖与全局已安装包中的已知恶意包及恶意版本。

## 功能特性

- 运行时依赖少（Python 3.10+；`rich` 用于实时仪表盘；在 3.10 上会自动安装 `tomli` 以解析 `pyproject.toml`）
- 三个子命令：`scan` / `global` / `check`
- 交互式终端下显示实时仪表盘：顶部 logo + 统计、左侧扫描路径/发现、右侧扫描进度、底部命中的恶意依赖（管道、`--json`/`--sarif`/`--quiet` 或非 TTY 时自动回退为顺序文本输出）
- 支持 Python 与 JS/TS 清单及锁文件
- 全局扫描：系统 Python、Node 全局（npm -g、pnpm -g、yarn global、nvm/fnm/volta）、Rust `cargo install`、Go `go install`（`go version -m` 解析依赖）
- 输出格式：终端表格 / JSON / SARIF
- API 限流（10 次/秒）
- 扫描过程按包显示进度；可用 `-o` 保存完整报告

## 安装

```bash
git clone <your-repo-url>
cd MisteyeDepscan
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

# 扫描当前项目
depscan scan .

# 扫描本机全局已安装包（系统 Python、Node 全局）
depscan global
```

在虚拟环境中安装后，激活 venv 即可使用其 `bin` 目录下的 `depscan`（例如 `.venv/bin/depscan`）。

### NVM 与 pnpm 常见路径

`depscan global` 会扫描 **npm -g**、**pnpm -g**、**yarn global**，以及 **nvm / fnm / volta** 各版本目录下的全局包（不仅限于当前激活的 `npm root -g`）。

| 工具 | 常见根目录 | 已安装 npm 包位置 |
|------|------------|-------------------|
| **nvm** | `~/.nvm`（或环境变量 `$NVM_DIR`） | `~/.nvm/versions/node/v<版本>/lib/node_modules/` |
| **pnpm 全局** | 因安装方式而异 | 运行 `pnpm root -g` 查看；macOS 常见 `~/Library/pnpm`，Linux 常见 `~/.local/share/pnpm` |

- 自定义目录树可用 `depscan scan <路径> --depth 0`。

也可不依赖 `PATH` 中的 `depscan` 命令：

```bash
python -m misteye_depscan scan .
```

### 安装后找不到 `depscan`？

`pip install` 会生成 `depscan` 脚本，但具体路径取决于 Python 版本与操作系统，可能不在 `PATH` 中。若 pip 提示 `The script depscan is installed in '...' which is not on PATH`，可按提示使用对应路径，或查询用户脚本目录：

```bash
python3 -m site --user-base
# 可执行脚本通常在：<输出路径>/bin
```

若要在全局使用，将该 `bin` 目录加入 shell 配置（路径随 Python 版本变化，请勿写死 `3.10`）：

```bash
export PATH="$(python3 -m site --user-base)/bin:$PATH"
```

写入 `~/.zshrc` 或 `~/.bashrc` 后重新打开终端。开发场景仍推荐使用上面的 venv 方式。

> **说明**：`python3 -m site --user-base` 中的 `site` 是 Python 标准库模块名，用于查询「用户级安装」根目录，不是让你手动指定路径。

### `depscan` 命令定义在哪？

在 [`pyproject.toml`](pyproject.toml) 中注册：

```toml
[project.scripts]
depscan = "misteye_depscan.cli:main"
```

安装后会生成入口脚本，调用 [`src/misteye_depscan/cli.py`](src/misteye_depscan/cli.py) 中的 `main()`。模块方式入口：[`src/misteye_depscan/__main__.py`](src/misteye_depscan/__main__.py)。

## API Key

在 [app.misteye.io/api-keys](https://app.misteye.io/api-keys) 申请免费 API Key。

方式一：环境变量

```bash
export MISTEYE_API_KEY="your-api-key"
```

方式二：配置文件（权限须为 `600`）

```bash
mkdir -p ~/.config/misteye
printf '%s' "$MISTEYE_API_KEY" > ~/.config/misteye/api_key
chmod 600 ~/.config/misteye/api_key
```

首次在无 Key 的交互式终端中运行时会提示输入并保存。

## 用法

```bash
# 扫描当前项目
depscan scan .

# 扫描指定目录
depscan scan /path/to/project

# 扫描 Mac 系统级全局环境（默认）
# - Python：Homebrew /usr/local / 系统 Framework 路径（排除项目 .venv）
# - Node：npm -g、pnpm -g、yarn global、nvm/fnm/volta 各版本下的全局包
depscan global

# 仅 Python / Node / Rust / Go 全局环境
depscan global --python-only
depscan global --node-only
depscan global --rust-only
depscan global --go-only

# 检查单个包
depscan check requests==2.32.3 --pypi
depscan check lodash@4.17.21 --npm

# JSON / SARIF（适合 CI）
depscan scan . --json
depscan scan . --sarif
depscan global --json

# 将完整报告保存到文件
depscan scan . -o report.json
depscan global -o global-report.json

# 控制扫描深度（默认 10 层）
depscan scan . --depth 20       # 扫更深
depscan scan . --depth 1        # 只扫根目录一级
depscan scan . --depth 0        # 无限深度（完整递归）
```

## 扫描结果与进度

每次扫描都会请求 MistEye API（不使用本地缓存），确保情报库更新后不会漏报。

### 进度输出

每完成一个包输出一行（并发扫描，顺序可能与依赖列表不一致）：

```text
[1/120] requests==2.32.3 → No threat record
[2/120] lodash@4.17.21 → No threat record
[3/120] evil-pkg@1.0.0 → Threat detected · critical
```

API 返回 `status: unknown` 时界面显示为 **No threat record**（绿色），而不是原始单词 `unknown`；这**不代表**该包一定安全。

保存完整报告：`depscan scan . -o report.json` 或 `depscan global -o global-report.json`。

静默模式：`--quiet`。关闭颜色：`depscan --no-color scan .` 或设置 `NO_COLOR=1`。

## 生态（自动检测）

与 MistEye 对齐：**npm**、**PyPI**、**Rust**、**Go**、**RubyGems** 支持自动检测并扫描。

| 生态 | 标记文件 | 状态 |
|------|----------|------|
| **npm** | `package.json`、`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml` | 已支持 |
| **PyPI** | `pyproject.toml`、`requirements*.txt`、`Pipfile`、`Pipfile.lock`、`poetry.lock`、`uv.lock`、`setup.py`、`setup.cfg` | 已支持 |
| **Rust** | `Cargo.toml`、`Cargo.lock`（workspace 优先根 `Cargo.lock`） | 已支持 |
| **Go** | `go.mod`、`go.sum`（同目录优先 `go.sum`） | 已支持 |
| **RubyGems** | `Gemfile`、`Gemfile.lock` | 已支持 |

**自动检测规则**

- 在项目目录树中查找标记文件，跳过 `node_modules/`、`vendor/`、`.venv/`、`venv/`、`.tox/`、`site-packages/`、`dist/`、`build/` 等目录。
- 跳过上述目录仅影响**清单文件的发现位置**；**`node_modules/` 下已安装的包仍会扫描**（读取各包的 `package.json`）。

**手动指定生态**

```bash
depscan scan . --ecosystem=npm
depscan scan . --ecosystem=pypi
depscan scan . --ecosystem=rust
depscan scan . --ecosystem=go
depscan scan . --ecosystem=rubygems
depscan scan . --ecosystem=all
depscan scan . --ecosystem=npm,pypi,rust,go,rubygems   # 省略时 = 自动检测

# 仅清单/锁文件（不扫描 node_modules 已安装树）
depscan scan . --no-node-modules
```

## 支持的依赖文件

**默认（自动检测 npm / PyPI / Rust / Go / RubyGems）**

- **PyPI**：`requirements*.txt`、`pyproject.toml`（PEP 621 + Poetry `[tool.poetry]`，含 `group.*.dependencies`）、`Pipfile`、`Pipfile.lock`、`poetry.lock`、`uv.lock`、`setup.py`、`setup.cfg`
- **npm**：`package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`，以及 `node_modules/**/package.json`
- **Rust**：`Cargo.lock`（workspace 根目录）
- **Go**：`go.sum`（有则优先于同目录 `go.mod`）
- **RubyGems**：`Gemfile`、`Gemfile.lock`

> **暂不支持 Java / Maven**。MistEye Detect API 目前没有 `package:maven` 类型，把 Maven 坐标按其他生态发送会产生误报，所以工具暂不解析 Java 依赖。

## API 响应

MistEye Detect API 使用 `status` 字段：

```json
{ "status": "malicious", "matches": [...] }
{ "status": "unknown", "matches": [] }
```

| API `status` | 含义 |
|---|---|
| `malicious` | 命中已知威胁情报 |
| `unknown` | 库中无记录（界面显示 **No threat record**；**不**表示一定安全） |

**退出码**

| 代码 | 含义 |
|------|------|
| 0 | 扫描完成，未发现恶意包（含 `unknown` 结果） |
| 1 | 发现恶意包或恶意版本 |
| 2 | 扫描未完成（API/网络/覆盖率问题） |
| 3 | 配置错误（路径无效、缺少 API Key 等） |

展示与调用 API 时：PyPI 使用 `name==version`；npm 等其他生态使用 `name@version`。**跨生态命中会被忽略**——比如扫描的是 PyPI 包，但 API 返回的 match.type 是 `package:npm`（npm 情报库中有同名恶意包），该条命中不会算作威胁，避免「PyPI/npm 同名包」造成的误报。

## 参考链接

- MistEye API 文档：https://app.misteye.io/api-docs
- MistEye API Key：https://app.misteye.io/api-keys
- MistEye Security Gate：https://github.com/slowmist/misteye-skills

## 许可证

MIT
