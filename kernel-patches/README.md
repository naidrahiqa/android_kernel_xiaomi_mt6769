# Kernel patches

## `kernelsu-susfs-2.4.0.patch`

KernelSU-side glue required by SUSFS v2.4.0. The `KernelSU/` submodule is
vendored from [backslashxx/KernelSU](https://github.com/backslashxx/KernelSU)
at `fdca332` (v3.3.1+, 32725) plus this patch applied on the local branch
`susfs-2.4.0` (commit `4142960`).

Touches:

| File | Purpose |
|---|---|
| `kernel/Kconfig` | `KSU_SUSFS*` config menu |
| `kernel/supercall/supercall.c` | `CMD_SUSFS_*` dispatch via `ksu_handle_sys_reboot` |
| `kernel/hook/setuid_hook.c` | umount / sus-path hooks on setresuid |
| `kernel/ksu.c` | susfs init + creds wiring |
| `kernel/preinit/preinit.h` | extra preinit hook slot |
| `kernel/selinux/selinux.c` | `selinux_hide` support |
| `kernel/feature/kernel_umount.c` | path_umount fallback for 4.14 |

Re-apply on a fresh submodule checkout:

```sh
git -C KernelSU checkout fdca332
git -C KernelSU apply ../kernel-patches/kernelsu-susfs-2.4.0.patch
```
