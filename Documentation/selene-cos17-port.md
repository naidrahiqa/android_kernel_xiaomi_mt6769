# Port ColorOS 17 ke Redmi 10 (selene) — Catatan Analisis dan Perbaikan

Dokumen ini mencatat analisis dan perbaikan untuk tiga masalah utama pada port
ColorOS 17 (Android 17) ke Xiaomi Redmi 10 (kode nama `selene`, SoC MediaTek
MT6769):

1. **IR remote mati** — aplikasi remote tidak bisa memancarkan sinyal.
2. **Earphone tidak berfungsi** — audio tidak keluar melalui jack 3,5 mm.
3. **Aplikasi/Chrome stuck di splash** — aplikasi tidak pernah selesai loading.

ROM dasar: Android 12 vendor `V14.0.7.0.TKUMIXM` + system/product/system_ext
ColorOS 17. Kernel yang berjalan: `4.14.357+17-Blissxdp-2026.10.31-s`
(commit `c53a8462cd`), sumber modifikasi di
`https://github.com/naidrahiqa/android_kernel_xiaomi_mt6769`.

Branch perbaikan: `cos17-fixes`, worktree
`/home/naidra/Projects/Kernel/mt6769-cos17-fixes`, berbasis `fork/lsm-xdp`
(`f3b635a930`).

---

## 1. IR remote mati

### Gejala

Aplikasi IR (Mi Remote dan sejenisnya) melaporkan "IR tidak tersedia" atau
tidak mengirim apa pun. Tidak ada emisi dari LED IR.

### Akar masalah

Ada dua lapisan yang tidak cocok antara framework ColorOS 17 dan vendor
Android 12:

1. **Permission product menandai fitur IR sebagai tidak tersedia.**
   `product/etc/permissions/ir_remote.xml` berisi
   `unavailable-feature android.hardware.consumerir`. Akibatnya
   `PackageManager` menyembunyikan fitur dari aplikasi dan
   `ConsumerIrService` tidak diinisialisasi.

2. **Framework Android 17 hanya mengenal HAL AIDL.**
   `ConsumerIrService` hasil decompile
   (`.work/dex/jadx/ConsumerIrService.java`) memanggil
   `android.hardware.ir.IConsumerIr/default` melalui
   `ServiceManager.waitForDeclaredService()`. Vendor ROM hanya menyediakan
   HAL HIDL `android.hardware.ir@1.0` (`android.hardware.ir@1.0-service`),
   sehingga service framework melempar error dan menonaktifkan IR.

Bukti tambahan:

- `system/system/etc/vintf/compatibility_matrix.202604.xml` mewajibkan
  `<hal format="aidl"><name>android.hardware.ir</name>` dengan interface
  `IConsumerIr/default`.
- `system/system/etc/selinux/plat_service_contexts` sudah memetakan
  `android.hardware.ir.IConsumerIr/default` ke `hal_ir_service`, dan
  `plat_sepolicy.cil` mengizinkan `hal_ir_server` menambahkannya. Jadi
  SELinux untuk HAL AIDL sudah siap di sisi platform.
- `vendor/etc/selinux/vendor_sepolicy.cil` memetakan `hal_ir_default` ke
  `hal_ir_server` dan sudah memberi akses ke `/dev/irtx`.
- Driver kernel `drivers/misc/mediatek/irtx/mtk_irtx_pwm.c` menyediakan
  `/dev/irtx` dengan ioctl `IRTX_IOC_SET_CARRIER_FREQ`,
  `IRTX_IOC_SET_DUTY_CYCLE`, dan `write()` untuk waveform PWM.
- `vendor/lib64/hw/consumerir.common.so` mengekspor simbol `HMI`
  (struktur `hw_module_t`) dan menangani sendiri pembukaan `/dev/irtx`,
  packing pola PWM MTK, dan ioctl. Modul ini bisa dipakai ulang.

### Rencana perbaikan

**Sisi kernel:** tidak ada perubahan diperlukan; driver IRTX sudah ada dan
aktif (`CONFIG_MTK_IRTX`/driver PWM terpasang pada defconfig build).

**Sisi ROM (overlay):**

1. Ganti isi `product/etc/permissions/ir_remote.xml` agar tidak lagi
   mendeklarasikan `unavailable-feature`; cukup deklarasikan fitur
   `android.hardware.consumerir` sebagai tersedia.
2. Tambahkan HAL AIDL `android.hardware.ir.IConsumerIr/default`:
   - Binary service baru di `/vendor/bin/hw/android.hardware.ir-service.selene`
     yang memakai `libbinder_ndk`, membuka
     `vendor/lib64/hw/consumerir.common.so` dengan `dlopen`, lalu memanggil
     `HMI->open()` dan method `transmit`/`get_carrier_freqs`.
   - Init rc dengan `interface aidl android.hardware.ir.IConsumerIr/default`
     dan `user system`/`group system`, serta `seclabel u:object_r:hal_ir_default:s0`.
   - Entri VINTF AIDL di `vendor/etc/vintf/manifest.xml` (menggantikan entri
     HIDL IR), plus hapus deklarasi HIDL `android.hardware.ir@1.0` bila tidak
     dipakai lagi.
3. Pastikan file context untuk binary baru:
   `/(vendor|system/vendor)/bin/hw/android\.hardware\.ir-service\.selene u:object_r:hal_ir_default_exec:s0`.
4. Hapus/Nonaktifkan service HIDL lama agar tidak bentrok (`disabled` di rc
   atau hapus binarnya).

Detail ABI AIDL yang harus diimplementasikan (dari decompile
`ConsumerIrService`):

- `transmit(int carrierFrequency, int[] pattern)` → `boolean`
- `getCarrierFreqs()` → `ConsumerIrFreqRange[]`
  (parcel: jumlah array, lalu pasangan `min`/`max` sebagai `int`)
- Kode transaksi binder: `transmit` = 1, `getCarrierFreqs` = 2.

### Catatan penting

Mengubah permission saja tanpa menyediakan HAL AIDL akan membuat
`system_server` crash saat start karena `ConsumerIrService` gagal
menemukan service. Kedua perubahan harus dilakukan bersamaan.

---

## 2. Earphone tidak berfungsi

### Gejala

Audio tidak keluar dari earphone saat jack 3,5 mm dicolok. Belum ada log
`dmesg`/`logcat`/`dumpsys audio` dari perangkat, sehingga diagnosis masih
sebagian hipotetis.

### Temuan sementara

- `vendor/etc/audio_policy_configuration.xml` menggunakan
  `halVersion="2.0"` dengan konfigurasi audio kustom ColorOS.
- Perlu diverifikasi apakah:
  - deteksi jack (headset/headphone) dilaporkan oleh driver codec MT6357;
  - `audio_policy` memilih device `AUDIO_DEVICE_OUT_WIRED_HEADSET`/
    `WIRED_HEADPHONE`;
  - HAL audio vendor (Audio HAL 2.0) menginisialisasi jalur output yang
    benar;
  - `audio_restart_boot.rc` memicu restart HAL terlalu dini.

### Rencana diagnosis

1. Ambil log saat jack dicolok:
   - `adb shell dmesg | grep -iE "headset|jack|accdet|mt6357"`
   - `adb shell dumpsys audio`
   - `adb shell dumpsys media.audio_flinger`
   - `adb logcat -b all -s AudioPolicyManager AudioFlinger AudioService`
2. Cek routing: `adb shell dumpsys audio | grep -A5 "Devices"`.
3. Bandingkan `audio_policy_configuration.xml` dengan ROM Android 12 asli
   (`V14.0.7.0.TKUMIXM`) untuk melihat apakah `halVersion`/route berbeda.
4. Bila perlu, uji dengan memaksa route lewat
   `adb shell cmd media_session` atau patch audio policy.

Perubahan `audio_restart_boot.rc`/`halVersion` **belum** dilakukan sampai
log tersedia, agar tidak menambah variabel baru.

---

## 3. Aplikasi/Chrome stuck di splash

### Gejala

Aplikasi (termasuk Chrome) berhenti di splash screen dan tidak pernah
masuk ke UI utama. Ini konsisten dengan proses aplikasi yang dibekukan
(freeze) oleh manajer memori ColorOS.

### Akar masalah

ROM ColorOS 17 mengaktifkan **HANS** (Hybrid App Notification Service),
manajer pembekuan aplikasi latar belakang OPLUS:

- `persist.vendor.enable.hans=true`
- `hans.rc`, `/system_ext/bin/hans`
- Daemon HANS membekukan proses aplikasi lewat cgroup v2 freezer
  (`cgroup.freeze`) dan mengharapkan kernel memberi tahu saat ada
  binder transaction, paket jaringan masuk, atau sinyal yang menargetkan
  proses beku.

Kernel `4.14.357+17-Blissxdp` **tidak memiliki** driver jembatan
`oplus_hans`, sehingga:

- HANS membekukan aplikasi tetapi tidak pernah menerima event thaw.
- Binder transaction ke proses beku tidak dilaporkan.
- Paket jaringan masuk tidak membangunkan aplikasi.
- Sinyal (SIGKILL/SIGTERM dan sejenisnya) tidak dilaporkan.

Hasilnya: aplikasi tetap beku saat dibuka dari launcher → splash
menggantung.

### Perbaikan (sudah diimplementasikan di branch `cos17-fixes`)

Driver built-in `oplus_hans` di `drivers/misc/oplus_hans/`:

- `hans.c` — family generic netlink `oplus_hans`, handshake `LOOP_BACK`,
  laporan event ke daemon, penanganan `PKG`, `FROZEN_TRANS`,
  `CPUCTL_TRANS`, dan negosiasi `HANS_USE_CGRPV2` (kode `-99`).
- `hans_binder.c` — hook binder/signal:
  - `hans_binder_trans()` — transaksi sinkron/async ke task beku.
  - `hans_binder_reply()` — balasan ke proses sistem yang beku.
  - `hans_binder_alloc()` — buffer async hampir penuh.
  - `hans_send_signal()` — sinyal ke task beku.
- `hans_netfilter.c` — hook `NF_INET_LOCAL_IN` IPv4/IPv6, pencocokan UID
  socket, dan pelaporan `HANS_PKG` saat paket TCP masuk.
- `include/linux/oplus_hans.h` — ABI pesan dan deklarasi hook.

Titik patch kernel:

- `drivers/android/binder.c`:
  - include `oplus_hans.h`;
  - panggilan `hans_binder_trans()`/`hans_binder_reply()` setelah target
    transaksi diketahui;
  - implementasi `binder_hans_check_frozen_transaction()` — memindai
    `binder_procs`, thread `todo`, `transaction_stack`, dan `proc->todo`
    untuk transaksi yang menunggu proses beku.
- `drivers/android/binder_alloc.c`: `hans_binder_alloc()` di
  `binder_alloc_new_buf_locked()`.
- `kernel/signal.c`: `hans_send_signal()` di `do_send_sig_info()`.
- `drivers/misc/Kconfig` + `Makefile`: wiring `CONFIG_OPLUS_FEATURE_HANS`.
- `arch/arm64/configs/selene_defconfig`: `CONFIG_OPLUS_FEATURE_HANS=y`.

Karena `CONFIG_MODVERSIONS=y`, driver dibuat **built-in** (`bool`), bukan
modul, agar tidak kena mismatch versi simbol.

### Verifikasi

Setelah flash kernel baru:

```sh
# pastikan driver terinisialisasi
adb shell dmesg | grep oplus_hans
# harapan: "HANS bridge initialized" dan "hans support cgroupv2"

# pastikan daemon HANS berjalan
adb shell getprop init.svc.hans
adb shell getprop sys.hans.enable

# uji dengan mematikan HANS (butuh root/KernelSU)
adb shell su -c 'setprop persist.vendor.enable.hans false'
adb shell su -c 'setprop ctl.stop hans'
# lalu buka Chrome: jika splash hilang, penyebabnya terkonfirmasi HANS
```

Untuk menyalakan kembali:

```sh
adb shell su -c 'setprop persist.vendor.enable.hans true'
adb shell su -c 'setprop ctl.start hans'
```

---

## Status implementasi

| Masalah | Status | Keterangan |
|---|---|---|
| IR mati | Analisis selesai, perbaikan ROM belum dibangun | Butuh build HAL AIDL + overlay permission/VINTF/init |
| Earphone | Menunggu log perangkat | Belum ada perubahan kode |
| Aplikasi stuck | Driver kernel selesai, compile-check lolos | Perlu build kernel penuh + flash + uji |

### Compile-check yang sudah dilakukan

```sh
cd /home/naidra/Projects/Kernel/mt6769-cos17-fixes
make -j4 ARCH=arm64 O=/tmp/opencode/build-selene \
  CROSS_COMPILE=aarch64-linux-gnu- CC=clang HOSTCC=clang \
  kernel/signal.o drivers/android/binder.o drivers/android/binder_alloc.o \
  drivers/misc/oplus_hans/hans.o drivers/misc/oplus_hans/hans_binder.o \
  drivers/misc/oplus_hans/hans_netfilter.o
```

Semua objek berhasil dikompilasi. Build kernel penuh dan flash belum
dilakukan pada tahap ini.

### Build kernel penuh (langkah berikutnya)

Gunakan toolchain yang sama dengan build kernel yang berjalan (clang
22.1.8 + binutils `aarch64-linux-gnu-`), lalu:

```sh
make -j$(nproc) ARCH=arm64 O=out \
  CROSS_COMPILE=aarch64-linux-gnu- CC=clang HOSTCC=clang \
  selene_defconfig
make -j$(nproc) ARCH=arm64 O=out \
  CROSS_COMPILE=aarch64-linux-gnu- CC=clang HOSTCC=clang
```

Hasil `out/arch/arm64/boot/Image`/`Image.gz-dtb` dipaketkan ke boot image
yang sesuai (header MediaTek MT6769), lalu flash lewat fastboot/recovery.

---

## Lampiran: referensi berkas

| Berkas | Fungsi |
|---|---|
| `.work/dex/jadx/ConsumerIrService.java` | Dekompilasi service IR framework |
| `.work/extracted/product/etc/permissions/ir_remote.xml` | Permission IR yang harus diubah |
| `.work/extracted/vendor/etc/vintf/manifest.xml` | Manifest VINTF vendor, entri IR HIDL |
| `.work/extracted/vendor/etc/init/android.hardware.ir@1.0-service.rc` | Init rc HAL IR lama |
| `.work/extracted/vendor/lib64/hw/consumerir.common.so` | Modul IR MTK yang dipakai ulang |
| `.work/extracted/system/system/etc/selinux/plat_service_contexts` | Mapping service AIDL IR |
| `.work/extracted/system/system/etc/vintf/compatibility_matrix.202604.xml` | Matriks kompatibilitas AIDL IR |
| `.work/extracted/vendor/etc/audio_policy_configuration.xml` | Konfigurasi audio kustom |
| `drivers/misc/oplus_hans/` | Driver jembatan HANS |
| `drivers/android/binder.c` | Hook binder + pemindai transaksi beku |
| `kernel/signal.c` | Hook sinyal HANS |
