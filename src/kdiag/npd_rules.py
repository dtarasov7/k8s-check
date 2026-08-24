import re


NPD_UPSTREAM_VERSION = "v0.8.25"
NPD_UPSTREAM_SOURCE = "https://raw.githubusercontent.com/kubernetes/node-problem-detector/v0.8.25/config/kernel-monitor.json"
NPD_UPSTREAM_LICENSE = "Apache-2.0"


# Semantically adapted from the pinned upstream kernel-monitor configuration.
# Categories are kdiag-local so upstream reason names can evolve independently.
NPD_CATEGORY_PATTERNS = (
    ("npd_task_hung", re.compile(r"\btask\s+.+\bblocked for more than\s+\w+\s+seconds\.?", re.I)),
    ("npd_unregister_netdevice", re.compile(r"unregister_netdevice:\s+waiting for\s+\S+\s+to become free\.\s+usage count\s*=\s*\d+", re.I)),
    ("npd_kernel_oops", re.compile(r"BUG:\s+(?:unable to handle kernel NULL pointer dereference|kernel NULL pointer dereference)|divide error:\s*0000\s+\[#\d+\]", re.I)),
    ("npd_ext4_error", re.compile(r"\bEXT4-fs error\b", re.I)),
    ("npd_ext4_warning", re.compile(r"\bEXT4-fs warning\b", re.I)),
    ("npd_io_error", re.compile(r"\bBuffer I/O error\b", re.I)),
    ("npd_xfs_shutdown", re.compile(r"\bXFS\b.*\bShutting down filesystem\b", re.I)),
    ("npd_memory_read_error", re.compile(r"\bCE memory read error\b", re.I)),
    ("npd_hardware_corrected", re.compile(r"\[Hardware Error\]:\s*event severity:\s*corrected\s*$", re.I)),
    ("npd_hardware_recoverable", re.compile(r"\[Hardware Error\]:\s*event severity:\s*recoverable\s*$", re.I)),
    ("npd_hardware_fatal", re.compile(r"\[Hardware Error\]:\s*event severity:\s*fatal\s*$", re.I)),
)
