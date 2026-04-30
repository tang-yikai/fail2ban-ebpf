# 手动测试


### 1. 测试 Signal 11 (SIGSEGV - 段错误)
这是模拟最危险的“内存破坏攻击”。

*   **测试步骤：**
    1.  开启一个 SSH 连接（保持在输入密码界面）：
        ```bash
        ssh user@127.0.0.1
        ```
    2.  在另一个终端找到这个 `sshd` 子进程的 PID：
        ```bash
        ps -ef | grep "sshd: user" | grep -v grep
        ```
    3.  **核心操作：** 使用 `kill` 命令向该子进程发送信号 11：
        ```bash
        sudo kill -11 <PID>
        ```
*   **预期结果：**
    *   eBPF 捕获到 `exit_signal = 11`。
    *   Go 日志应显示：`event=preauth_short_conn exit_signal=11 reason=SIGSEGV`。
    *   **封禁结果：** IP 应该被立刻封禁，无需等待第 2 次。

---

### 2. 测试 Signal 4 (SIGILL - 非法指令)
这是模拟攻击者尝试执行错误的 Shellcode。

*   **测试步骤：**
    1.  同上，开启一个 SSH 连接。
    2.  向该子进程发送信号 4：
        ```bash
        sudo kill -4 <PID>
        ```
*   **预期结果：**
    *   eBPF 捕获到 `exit_signal = 4`。
    *   Go 逻辑应识别该高危信号并实现“一次即封”。


### 3. telne短时间链接

```bash
timeout 1s telnet 127.0.0.1 22
```