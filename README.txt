校园网自动登录 · 安装说明
========================

需要：Ubuntu / Debian（有 systemd），Python 3.7 以上（系统自带，无需安装任何库）

安装
----
1. 把整个文件夹解压到任意位置，进入该目录
2. 执行：

       sudo bash install.sh

3. 按提示输入：
   - 学号 / 账号
   - 密码（输入两次，不显示）
   - 接入方式：直接回车（默认「实验室」）
   - 自动登录时段：直接回车（默认 07:00-22:30，晚上断网就保持默认）

装完会自动测试一次登录并告诉你结果。之后开机会自动后台运行。

常用命令
--------
  看状态    systemctl status campus-login --no-pager
  看日志    journalctl -u campus-login -f
  改配置    sudo nano /opt/campus-login/config.json
            改完执行 sudo systemctl restart campus-login
  卸载      sudo bash install.sh --remove

说明
----
- 只在校园网未认证时才会发登录请求；插网线或用别的网络时自动跳过
- 22:30 之后到次日 07:00 完全静默，不探测也不重试
- 连续登录失败会自动拉长重试间隔，避免触发验证码
