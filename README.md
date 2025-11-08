#  FuckYourACE

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/v/release/xiaoxinmm/FuckYourACE.svg?style=flat-square)](https://github.com/xiaoxinmm/FuckYourACE/releases)

<center> 

# ![logo](icon.png)
**一个专治进程 CPU 占用过高的小工具。（请管理员运行！）**

</center> 

## 🖥️ 界面预览
![FuckYourACE 运行截图](FYourACE_screenshot.png)

## 🎨 它解决了什么问题？

你是否在玩某些游戏时，被 `SGuard64.exe` 或 `SGuardSvc64.exe` 这类后台进程搞得 CPU 占用飙升，导致游戏掉帧或系统卡顿？

这些是“安全管理类程序”，你不能（也不应该）轻易地终止它们，否则可能导致游戏闪退或账号异常。

本工具就是为了解决这个问题而生的。它不会关闭这些进程，而是“温和”地限制它们，把它们“关小黑屋”，让你的 CPU 资源可以重新回到游戏本身。

本工具不会关闭程序运行，只会让他降低资源利用率，并不妨碍程序本身保护用户。



## 💡 它是如何工作的？

本程序启动后，会立即开始一个**无限循环**，每 60 秒执行一次以下“体检和限制”流程：

1.  **自动巡检**：扫描当前系统中的所有进程。
2.  **识别目标**：查找名为 `SGuard64.exe` 和 `SGuardSvc64.exe` 的目标进程。
3.  **寻找“小黑屋”**：
    * **首选方案**：通过 Windows API 查找 CPU 的**能效核（E-Cores）**。
    * **备用方案**：如果系统没有 E-Core（例如 AMD 平台或较旧的 Intel CPU），则自动选择**最后一个逻辑核心**作为目标。
4.  **执行限制**：
    * 将所有找到的目标进程，强制**绑定（Affinity）**到那个单独的“小黑屋”核心上。
    * 将这些进程的 CPU 优先级设置为**“最低”（Idle）**。
5.  **循环往复**：完成上述操作后，程序会显示一个 60 秒倒计时，然后重复整个流程，以确保设置持续生效，防止目标进程“越狱”。


---

## 🚀 如何使用 (面向用户)

1.  前往本项目的 [**Releases 页面**](https://github.com/xiaoxinmm/FuckYourACE/releases)（你需要先在 GitHub 上创建 Release 并上传打包好的程序）。
2.  下载最新的 `FuckYourACE.exe` 文件。
3.  **直接双击运行**。程序启动时会自动请求管理员权限（因为修改进程需要高权限）。
4.  程序启动后会显示日志，并自动开始循环执行。你只需将它最小化即可。

> **日志文件**：程序运行日志会自动保存在 `C:\Users\AppData\Roaming\FuckYourACE\app.log`，方便排查问题。

## 🛠️ 如何构建 (面向开发者)

本项目基于 [Wails v2](https://wails.io/) 和 Go 构建。

1.  **克隆仓库**
    ```bash
    git clone https://github.com/xiaoxinmm/FuckYourACE.git
    cd FuckYourACE
    ```
2.  **安装前端依赖**
    ```bash
    cd frontend
    npm install
    cd ..
    ```

3.  **构建应用**
    ```bash
    wails build
    ```

4.  **运行**
    构建好地可执行文件位于 `build/bin/FuckYourACE.exe`。


## ⚠️ 免责声明 (Disclaimer)

**本项目仅供技术研究和学习使用。**

任何通过修改系统进程设置（如 CPU 亲和性、进程优先级）来影响其他软件（尤其是反作弊软件）的行为都**存在潜在风险**。

您必须充分理解本工具的功能，并**自行承担**使用本工具可能导致的一切后果，包括但不限于游戏账号限制、封禁或系统不稳定。

**作者不对任何因使用或滥用本工具而造成的直接或间接损失负责。**

**如果您不理解或不同意上述条款，请立即停止使用并删除本程序。**

## 📜 许可 (License)

本项目采用 [MIT License](LICENSE) 授权。

