# TL-ICScan Linux 小白安装指南

> 本指南专为 Linux 新手用户编写，将手把手带您完成 TL-ICScan 的安装和部署。

## 目录

- [安装前准备](#安装前准备)
- [方式一：Docker 部署（推荐）](#方式一docker-部署推荐)
- [方式二：源码安装（本指南重点）](#方式二源码安装本指南重点)
- [验证安装](#验证安装)
- [常见问题](#常见问题)
- [下一步](#下一步)

---

## 安装前准备

### 1. 确认您的 Linux 系统

本工具支持以下 Linux 发行版：

- Ubuntu 20.04 或更高版本
- Debian 10 或更高版本
- CentOS 7 或更高版本
- Fedora
- 其他主流 Linux 发行版

**如何查看您的系统版本？**

打开终端（Terminal），输入以下命令：

```bash
cat /etc/os-release
```

您会看到类似这样的输出：

```
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
```

### 2. 确保有网络连接

安装过程需要从互联网下载软件包，请确保：

- 您的电脑已连接到互联网
- 可以正常访问国内外网站（部分依赖来自国外服务器）

### 3. 准备好终端

在 Ubuntu/Debian 系统中：

- 按 `Ctrl + Alt + T` 快捷键打开终端
- 或者在应用程序菜单中搜索 "Terminal"

### 4. 磁盘空间检查

确保您有足够的磁盘空间（至少 2GB 可用空间）：

```bash
df -h ~
```

查看输出中 "Avail" 列，确保有至少 2GB 可用空间。

---

## 方式一：Docker 部署（推荐）

如果您已经安装了 Docker，这是最简单的部署方式。

### 步骤 1：检查是否已安装 Docker

```bash
docker --version
docker-compose --version
```

如果显示版本号，说明已安装。如果提示命令找不到，请先安装 Docker：

**Ubuntu/Debian 安装 Docker：**

```bash
# 更新软件包索引
sudo apt update

# 安装必要的依赖
sudo apt install -y ca-certificates curl gnupg

# 添加 Docker 官方 GPG 密钥
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 添加 Docker 仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装 Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 将当前用户添加到 docker 组（避免每次使用 sudo）
sudo usermod -aG docker $USER

# 重新登录或运行以下命令使组权限生效
newgrp docker
```

### 步骤 2：下载项目代码

```bash
# 进入您的工作目录（例如桌面）
cd ~/Desktop

# 克隆项目代码
git clone https://github.com/tianlusec/TL-ICScan.git

# 进入项目目录
cd TL-ICScan
```

如果提示 `git: command not found`，先安装 git：

```bash
sudo apt install -y git
```

### 步骤 3：启动 Docker 服务

```bash
# 启动 Web 界面
docker-compose up -d
```

启动成功后，打开浏览器访问：http://localhost:8501

### 步骤 4：初始化数据（可选）

首次使用建议更新数据：

```bash
docker-compose run --rm updater
```

这个过程可能需要几分钟，请耐心等待。

---

## 方式二：源码安装（本指南重点）

如果您不想使用 Docker，或者遇到 Docker 问题，可以选择源码安装。这种方式对新手稍微复杂一些，但我们会一步一步带您完成。

### 第一步：下载项目代码

```bash
# 1. 打开终端，进入您想存放项目的目录
# 例如：进入桌面
cd ~/Desktop

# 或者进入用户主目录
cd ~

# 2. 克隆项目（下载代码）
git clone https://github.com/tianlusec/TL-ICScan.git

# 3. 进入项目目录
cd TL-ICScan
```

**如果提示 `git: command not found`：**

```bash
# Ubuntu/Debian 用户
sudo apt update
sudo apt install -y git

# CentOS/RHEL 用户
sudo yum install -y git

# Fedora 用户
sudo dnf install -y git
```

安装 git 后，再次运行上面的 `git clone` 命令。

### 第二步：安装 Rust 编译环境

TL-ICScan 的核心引擎使用 Rust 语言开发，需要先安装 Rust 编译器。

```bash
# 1. 下载并安装 Rust（这个命令会询问您是否继续，输入 1 然后回车）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. 按照提示，选择默认安装（输入 1 然后按回车）

# 3. 安装完成后，加载 Rust 环境变量
source $HOME/.cargo/env

# 4. 验证安装
rustc --version
```

您应该看到类似 `rustc 1.xx.x` 的版本信息。

**如果 `curl` 命令失败：**

```bash
# Ubuntu/Debian 用户
sudo apt install -y curl

# CentOS/RHEL 用户
sudo yum install -y curl
```

### 第三步：编译 Rust 核心工具

这是关键步骤，会将 Rust 源代码编译成可执行程序。

```bash
# 1. 进入 Rust 核心目录
cd tianlu-intel-core

# 2. 开始编译（这个过程可能需要 2-5 分钟，请耐心等待）
cargo build --release

# 3. 编译完成后，回到项目根目录
cd ..
```

编译过程中您会看到很多输出信息，这是正常的。最后如果看到 "Finished release" 字样，说明编译成功。

**编译完成的程序位置：**

- 位置：`tianlu-intel-core/target/release/tianlu-intel-core`

**常见编译问题：**

如果编译失败，可能缺少系统依赖，尝试安装：

```bash
# Ubuntu/Debian
sudo apt install -y build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel

# Fedora
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y openssl-devel
```

### 第四步：安装 Python 环境

采集脚本使用 Python 编写，需要 Python 3.8 或更高版本。

```bash
# 1. 检查 Python 版本
python3 --version
```

如果版本低于 3.8，需要升级 Python（Ubuntu 20.04+ 默认已满足要求）。

**如果没有 Python 3：**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# CentOS/RHEL 8+
sudo yum install -y python3 python3-pip

# Fedora
sudo dnf install -y python3 python3-pip
```

### 第五步：安装 Python 依赖包

```bash
# 1. 确保在项目根目录（TL-ICScan）
cd ~/Desktop/TL-ICScan  # 根据您的实际路径调整

# 2. 升级 pip（Python 包管理器）
python3 -m pip install --upgrade pip

# 3. 安装项目依赖（这个过程可能需要 1-3 分钟）
pip3 install -r requirements.txt
```

**如果遇到权限错误：**

```bash
# 使用 --user 参数安装到用户目录
pip3 install --user -r requirements.txt
```

**如果 pip 安装速度很慢：**

可以使用国内镜像源加速：

```bash
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 第六步：初始化数据库并采集数据

现在所有工具都已安装完成，接下来初始化数据库并采集漏洞情报。

```bash
# 确保在项目根目录
cd ~/Desktop/TL-ICScan  # 根据您的实际路径调整

# 给更新脚本添加执行权限
chmod +x update_all.sh

# 运行数据采集（首次运行可能需要 2-5 分钟）
./update_all.sh
```

**您会看到的输出：**

```
Database initialized at tianlu_intel_v2.db
Updating NVD...
Updating CISA KEV...
Updating MSRC...
Updating Exploit-DB...
Updating EPSS...
Updating GitHub PoC...
All updates completed.
```

**数据库文件位置：**

- 文件名：`tianlu_intel_v2.db`
- 位置：项目根目录
- 大小：约 100-150MB

### 第七步：启动 Web 界面

数据准备好后，启动 Web 界面查看漏洞情报。

```bash
# 启动 Web 服务
streamlit run web_ui/dashboard.py
```

**成功启动后，您会看到：**

```
You can now view your Streamlit app in your browser.

Local URL: http://localhost:8501
Network URL: http://192.168.x.x:8501
```

打开浏览器，访问 `http://localhost:8501` 即可看到漏洞情报仪表盘！

**如何停止 Web 服务：**

- 在终端按 `Ctrl + C` 即可停止

---

## 验证安装

### 1. 验证 Rust 工具

```bash
# 查看最新的 5 条漏洞记录
./tianlu-intel-core/target/release/tianlu-intel-core list --limit 5 --db tianlu_intel_v2.db
```

您应该看到一个表格，显示最新的漏洞信息。

### 2. 验证数据库

```bash
# 检查数据库文件是否存在
ls -lh tianlu_intel_v2.db
```

应该显示一个 100MB 以上的文件。

### 3. 验证 Web 界面

打开浏览器访问 http://localhost:8501，您应该看到：

- 顶部有导航菜单
- 数据统计仪表盘
- 漏洞列表和搜索功能

---

## 常见问题

### Q1: 命令提示 "Permission denied"（权限被拒绝）

**解决方法：**

```bash
# 给脚本添加执行权限
chmod +x update_all.sh

# 或者使用 bash 直接运行
bash update_all.sh
```

### Q2: 编译 Rust 时报错 "linker `cc` not found"

**原因：** 缺少 C 编译器

**解决方法：**

```bash
# Ubuntu/Debian
sudo apt install -y build-essential

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
```

### Q3: pip 安装依赖时报错

**常见错误 1：** "Could not find a version that satisfies the requirement"

```bash
# 升级 pip 到最新版本
python3 -m pip install --upgrade pip
```

**常见错误 2：** "Permission denied"

```bash
# 使用 --user 参数
pip3 install --user -r requirements.txt
```

### Q4: 数据采集很慢或超时

**原因：** 没有配置 API Key，受速率限制

**解决方法（可选）：**

1. 注册 NVD API Key（免费）：https://nvd.nist.gov/developers/request-an-api-key

2. 设置环境变量：

```bash
export NVD_API_KEY="your-api-key-here"
./update_all.sh
```

3. 注册 GitHub Token（可选）：https://github.com/settings/tokens

```bash
export GITHUB_TOKEN="your-github-token-here"
./update_all.sh
```

### Q5: Web 界面无法访问

**检查步骤：**

1. 确认 Streamlit 正在运行（终端没有报错）
2. 检查端口是否被占用：

```bash
# 查看 8501 端口是否在使用
netstat -tulnp | grep 8501
# 或
ss -tulnp | grep 8501
```

3. 尝试更换端口：

```bash
streamlit run web_ui/dashboard.py --server.port 8502
```

然后访问 http://localhost:8502

### Q6: 如何更新数据？

建议每天运行一次更新：

```bash
cd ~/Desktop/TL-ICScan
./update_all.sh
```

**自动更新（可选）：**

使用 cron 定时任务每天自动更新：

```bash
# 编辑 crontab
crontab -e

# 添加以下行（每天凌晨 2 点更新）
0 2 * * * cd /home/你的用户名/Desktop/TL-ICScan && ./update_all.sh >> /tmp/tl-icscan-update.log 2>&1
```

记得将 `/home/你的用户名/Desktop/TL-ICScan` 替换为您的实际项目路径。

### Q7: 如何卸载？

```bash
# 1. 停止 Web 服务（如果正在运行）
# 按 Ctrl+C 停止

# 2. 删除项目目录
rm -rf ~/Desktop/TL-ICScan

# 3. 卸载 Rust（可选）
rustup self uninstall

# 4. 卸载 Python 包（可选）
pip3 uninstall -y streamlit pandas watchdog defusedxml ijson
```

---

## 下一步

安装完成后，您可以：

### 1. 定制关注列表

编辑 `watchlist.yml` 文件，添加您关注的厂商和产品：

```bash
# 使用文本编辑器打开
nano watchlist.yml
# 或
gedit watchlist.yml
# 或
vim watchlist.yml
```

示例配置：

```yaml
- name: "我的服务器环境"
  vendors: ["microsoft", "redhat", "ubuntu"]
  products: ["windows_server_2019", "rhel_8", "ubuntu"]
  severity_min: "HIGH"

- name: "Web 应用组件"
  keywords: ["apache", "nginx", "php", "mysql"]
  epss_min: 0.1
```

### 2. 生成情报简报

根据关注列表生成漏洞简报：

```bash
./tianlu-intel-core/target/release/tianlu-intel-core digest \
  --config watchlist.yml \
  --since 7d \
  --db tianlu_intel_v2.db \
  > weekly_report.md
```

生成的简报将保存为 `weekly_report.md` 文件，可以用任何文本编辑器或 Markdown 阅读器查看。

### 3. 查询特定漏洞

```bash
# 查询特定 CVE
./tianlu-intel-core/target/release/tianlu-intel-core show CVE-2024-12345 --db tianlu_intel_v2.db

# 查询高危漏洞
./tianlu-intel-core/target/release/tianlu-intel-core list --severity HIGH --limit 20 --db tianlu_intel_v2.db

# 查询有 PoC 的漏洞
./tianlu-intel-core/target/release/tianlu-intel-core list --has-poc --limit 20 --db tianlu_intel_v2.db

# 导出为 CSV
./tianlu-intel-core/target/release/tianlu-intel-core export --format csv --output vulnerabilities.csv --db tianlu_intel_v2.db
```

### 4. 集成到工作流

您可以将 TL-ICScan 集成到您的安全运营工作流中：

- 每日自动更新数据
- 定期生成简报发送给团队
- 与资产管理系统对接
- 配合告警系统使用

---

## 获取帮助

如果遇到本指南未覆盖的问题：

1. **查看项目文档**：https://github.com/tianlusec/TL-ICScan
2. **提交 Issue**：https://github.com/tianlusec/TL-ICScan/issues
3. **参与讨论**：https://github.com/tianlusec/TL-ICScan/discussions

---

## 附录：系统要求总结

| 组件     | 最低要求                            | 推荐配置                 |
| -------- | ----------------------------------- | ------------------------ |
| 操作系统 | Ubuntu 20.04 / Debian 10 / CentOS 7 | Ubuntu 22.04 / Debian 12 |
| Python   | 3.8+                                | 3.10+                    |
| Rust     | 1.70+                               | 最新稳定版               |
| 内存     | 2GB                                 | 4GB+                     |
| 磁盘空间 | 2GB                                 | 5GB+                     |
| 网络     | 稳定互联网连接                      | 高速网络（加速数据采集） |

---

**祝您使用愉快！**

如果这份指南对您有帮助，欢迎给项目点个 Star ⭐