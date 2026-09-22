# talus-monitor — PyPI installer for Talus

**Talus** is a kernel-level ransomware detection & response agent for Linux:
eBPF tracepoints hook syscalls, a per-PID sliding window scores file-open
behaviour, and the response layer can terminate the offending process the
moment a verdict fires. Measured: ~280,000 events/s at ~7.6% CPU.

This PyPI package is an **installer/runner** for the official prebuilt binary
(published on GitHub releases). It is pure Python, stdlib-only, and does not
bundle the agent itself.

```bash
pip install talus-process-monitor

talus-monitor install          # fetches the latest release binary (~1.7 MB)
sudo talus-monitor run monitor --diagnose     # 5-second end-to-end self-check
sudo talus-monitor run monitor                # observe mode
sudo talus-monitor run monitor --auto-kill    # EDR mode (Enterprise license)
```

Prefer building from source?

```bash
git clone https://github.com/BartoszOsiej/talus-process-monitor.git
cd talus-process-monitor && ./build.sh
sudo ./target/release/process-monitor monitor
```

- Free agent, MIT: https://github.com/BartoszOsiej/talus-process-monitor
- Deployment & tuning playbook: https://bartoszosiej.github.io/talus-process-monitor/field-guide.html
- Comparison vs Falco/Wazuh/Tracee: https://bartoszosiej.github.io/talus-process-monitor/comparison.html

Requires Linux with BTF (CO-RE) support and root or CAP_BPF/CAP_SYS_ADMIN to
load the eBPF program. The binary runs on x86_64 Linux.
