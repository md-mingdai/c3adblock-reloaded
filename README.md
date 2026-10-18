# esp32-c3-adblock

一个 **Pi-hole 风格的 DNS 广告拦截器**，跑在**两美元的 ESP32-C3** 上——*不需要 PSRAM*。

很多人没注意到的窍门：屏蔽列表根本不用塞进 RAM。把域名做成**排好序的 40 位哈希**存进闪存，查找时二分即可。14 万多个域名只占约 0.7 MB 闪存，匹配一次约 10 ms，RAM 只吃**约 50 KB**。

```
查询进来 ──▶ 提取域名 ──▶ FNV-1a 哈希（连同各级父域名后缀）
         ──▶ 在闪存哈希表里二分查找
              ├─ 命中  ──▶ 回 0.0.0.0   （黑洞）
              └─ 未命中 ──▶ 转发给上游解析器，把回复原样送回
```

## 为什么有意思

大多数 ESP32 DNS 黑洞方案会把屏蔽列表（域名字符串）整个读进 RAM，所以离不开 PSRAM。这个项目改存固定的 **5 字节（40 位）哈希，放在闪存里**：

| | 字符串放 RAM | 本方案（哈希放闪存） |
|---|---|---|
| 硬件 | ESP32 + PSRAM（约 8 美元） | ESP32-C3，无 PSRAM（约 2 美元） |
| 141k 域名 | 约 2.5 MB RAM | **0.67 MB 闪存** |
| RAM 占用 | 几乎吃满 | **约 50 KB** |
| 查找方式 | 字符串比较 | 约 18 次闪存读取（含 WiFi RTT 约 10 ms） |
| 碰撞 | 不适用 | 141k 时 0 次（537k 时 1 次） |

**为什么是 40 位？** 在这个闪存预算下，40 位是最佳平衡点。碰撞率遵循生日界——141k 域名时基本为 0，537k 时约 1 次（也就是有一个倒霉域名会被误杀）。降到 32 位能省 20% 闪存，但 250k 时会有约 7 次碰撞；升到 64 位则每个域名多花 3 字节，去解决一个根本不存在的问题。

这招在大芯片上同样成立——它不是为 C3 打的补丁。换到 16 MB 的 ESP32-S3，这些哈希能装下**约 270 万域名**，而字符串塞进 8 MB PSRAM 也只能放约 46.6 万。闪存哈希基本在所有场景都碾压 PSRAM 字符串；C3 只是让这个结论显得无可辩驳。

## 硬件

- 任意 **ESP32-C3** 开发板（在 C3 SuperMini 上实测过），4 MB 闪存，**不需要 PSRAM**
- 经典 **ESP32**（DevKit / WROOM，4 MB）也能编译：`pio run -e esp32dev -t upload`（社区贡献，已通过编译测试；C3 才是实测目标）
- 请用**稳定的 USB 电源**供电（手机充电器或路由器的 USB 口都行）。
  劣质或松动的 USB-C→A 转接头可能在 WiFi 发射时把板子拉到掉电。
- 配一个 **USB-A → USB-C 转接头**，就能直接插在大多数路由器背面的空闲 USB 口上——不用另配电源，也不用多一个盒子。

### 外壳

C3 SuperMini 的可打印外壳：[`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

打印提示：
- 不需要支撑；0.2 mm 层高、约 15% 填充就够。
- **天线一端要留空。** C3 的 PCB 天线是 USB-C 口对面那条短边上的锯齿走线——别用实心塑料把它埋了，也别在旁边放金属，否则 RSSI 会很难看。
- 通风口别堵：板子空闲温度大概在 45–55 °C。

## 踩过的坑（血泪教训）

- **ModemManager**（Fedora/Ubuntu 默认开着）会抢占 `/dev/ttyACM0` 并来回拨 DTR/RTS，结果就是**把 C3 复位**、串口也占住。修法：
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- **Snap 版 Chromium 权限**：如果你在 Ubuntu 上使用 Snap 安装的 Chromium，由于沙盒限制，即使连接了板子也可能看到“找不到兼容设备”。需要手动授予 USB 访问权限：
  ```bash
  sudo snap connect chromium:raw-usb
  ```
- C3 的 USB-Serial-JTAG 控制台在主机连上之前会吞掉早期启动输出（加 `while(!Serial)` 有帮助）。
- DNS 客户端会带 **EDNS OPT** 记录；被屏蔽的回复必须只包含问题 + 答案（ANCOUNT=1，NSCOUNT=ARCOUNT=0），否则就是畸形包。

## 编译与烧录（PlatformIO）

USB 烧一次就能跑起来——之后**固件和屏蔽列表都能走 WiFi 更新**（见下文）。

> ⚠️ 请用**新版 PlatformIO**——VSCode PlatformIO 扩展自带的核心，或者在 venv 里 `pip install -U platformio`。发行版/apt 里的 `platformio` 包（比如 4.3.4）太老，会报 `AttributeError: ... 'resultcallback'` 失败（issue #4）。`docs/` 下还托管了一个网页一键安装器（见下文）。

```bash
# 1. 复制密钥模板（已 gitignore，只留在本地）然后编辑：
#    - WIFI_SSID / WIFI_PASS 可选——留占位符，改用
#      设备端配网门户（见下文）。
#    - WEB_USER / WEB_PASS / OTA_PASS 不可选：它们守着仪表盘的
#      写操作接口（/ban、/addblock、/upload、/update、/setupdate、
#      /forgetwifi）和网络 OTA。请填真实值——这些接口以前对
#      LAN 上任何人都完全敞开。
cp src/secrets.example.h src/secrets.h
#    然后编辑 src/secrets.h

# 2. 生成屏蔽列表哈希表（默认 = StevenBlack 基础 + Hagezi Light，
#    约 10 万条，对 WhatsApp/社交友好）
python3 tools/build_blocklist.py data/blocklist.bin

# 3. 烧录固件 + 屏蔽列表文件系统（唯一一次 USB 烧录）
pio run -t upload
pio run -t uploadfs

# 4. 看它启动，记下 IP / 打开仪表盘
pio device monitor          # -> http://c3adblock.local
```

### 浏览器安装器

`docs/` 目录就是一个完整、**自包含**的网页一键安装器：里面放着固件镜像、屏蔽列表文件系统镜像，以及 `esp-web-tools` 的 JS 依赖

`docs/manifest.json` 描述的是分区偏移；刷新二进制时**不用改**它——CI 的 `web-installer` 任务会把新的 `firmware.bin` / `littlefs.bin` 提交进 `docs/`，安装器下次推送就能拿到。

### 使用自己的屏蔽列表

`build_blocklist.py OUT.bin [SOURCE ...]` 可以混合传入任意 URL 和本地文件，支持下面这些格式：

- **hosts 文件**——`0.0.0.0 ads.example.com tracker.example.com`（同一行里的域名全部收录）
- **纯域名列表**——一行一个域名
- **AdGuard / Adblock 基础规则**——`||ads.example.com^` 表示屏蔽，`@@||ok.example.com^` 表示放行某个域名（比如镜像 AdGuard Home 的允许列表）

被屏蔽的域名会连带屏蔽它的子域名。DNS 哈希列表表达不了的规则（正则、通配符、`$` 修饰符、外观类 `##` 规则）会被跳过并计数。`@@` 规则只能放行那一条精确条目——没法从被屏蔽的父域名底下单独放行某个子域名。如果某个源下载失败，构建会直接中止，而不是悄悄给你一份更小的列表（可用 `--allow-missing` 覆盖）。

### WiFi 配网（不用重烧固件）

如果连不上（或者你压根没配 `secrets.h`），它会开一个开放热点 **`C3-AdBlock-XXXX`**，带强制门户——用手机连上，选网络，输密码，搞定。以后要换网络：点仪表盘上的 **Forget WiFi**，或者开机时按住 **BOOT** 键，配网门户会重新出现。（`/forgetwifi` 现在要认证了，不再是那种随便访问的裸 URL——见下面安全一节。）

## OTA（告别 USB）

仪表盘 **http://c3adblock.local** 一站搞定：

- **屏蔽列表**——把新生成的 `blocklist.bin` 拖进 *Blocklist → Upload*；或者在 *Remote auto-update* 里填个 URL，设备就会按计划去拉预构建的 `blocklist.bin`。默认列表**每周一**由 GitHub Actions 重新构建并发布到一个固定 URL，粘一次就能让设备自己保持更新：
  `https://github.com/M-Abozaid/esp32-c3-adblock/releases/download/blocklist/blocklist.bin`
- **固件**——在 *Firmware → OTA update* 里上传 `.pio/build/c3/firmware.bin`；设备会校验后重启进新镜像。也可以从命令行走 WiFi 推：
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```

**4 MB 闪存的取舍：** 固件 OTA 需要*两个*应用槽，留给屏蔽列表的就只剩约 1.3 MB（**最多约 25 万域名**）。那个激进的 537k “终极版”列表只能放在单应用分区表里（不能固件 OTA）。取舍在 `partitions.csv` 里选。

## 安全

仪表盘的只读视图（`/`、`/stats.json`）保持开放，但所有写操作接口都要求 **HTTP Basic Auth**（凭据来自 `secrets.h` 里的 `WEB_USER`/`WEB_PASS`）：

- `/ban`、`/addblock`、`/unblock`、`/forgetwifi`
- `/upload`、`/update`（屏蔽列表和固件 OTA）
- `/setupdate`、`/fetchnow`
- `/setupstream`、`/resetupstream`（上游 DNS 解析器）

网络 OTA（`ArduinoOTA`，比如 `pio run -t upload --upload-port c3adblock.local --upload-protocol espota`）需要同一个文件里的 `OTA_PASS`。

没有这层保护，任何能在 LAN 上访问设备的人，都能零凭据把它刷成任意固件、或者改掉屏蔽列表——考虑到这台设备坐在你网络每一个 DNS 查询的必经之路上，这事挺值得在意。自定义屏蔽的域名在仪表盘渲染前也会做 HTML 转义，堵住了一条存储型 XSS：一个带标记的域名字符串（通过 `/addblock` 添加）否则会在浏览者的浏览器里执行。

**这里的 Basic Auth 是 LAN 信任边界上的管控，不是加密。** 一切都是 :80 上的明文 HTTP——这芯片根本没有余力跑 TLS 服务端。Basic Auth 凭据只是 base64（不是加密），而且每个认证请求都会带上；任何能嗅探你 LAN 流量的人（开放/访客 WiFi、ARP 欺骗）都能从线上直接读到。它防的是常见情况——你网络里另一台设备不带凭据来调 API，或者某个浏览器标签页对它发起 CSRF——而不是路径上的中间人。

**缓存 Basic Auth 带来的 CSRF：** 浏览器会自动把缓存的 Basic Auth 凭据带上，附加到对已认证源的*任何*后续请求——包括同一个浏览器之后访问的、完全无关的页面所触发的请求（比如 `<img src="http://c3adblock.local/forgetwifi">`，连 JS 都不需要）。只要你登录过一次仪表盘，任何网页都能悄悄调用这套 API，跟 LAN 上是谁无关。上面每个写操作接口现在都额外要求一个自定义头 `X-Requested-With: c3-adblock`，普通的 `<img>`/自动提交的 `<form>` 类 CSRF 加不上这个头（只有同源 `fetch()` 能加，仪表盘自己的 JS 就是这么干的）——这也是为什么 `/forgetwifi` 不再是能直接访问的裸 URL，请改用仪表盘按钮。

**默认凭据：** 如果 `secrets.h` 里还是 `secrets.example.h` 中的占位符 `CHANGE_ME_WEB_PASSWORD` / `CHANGE_ME_OTA_PASSWORD`，设备就会带着一个公开的“密码”启动（它就躺在本仓库的示例文件里）。固件会通过串口打警告，仪表盘上也会显示横幅——但它照样启动、照样跑，所以在你不完全掌控的网络上放心使用之前，务必先在 `secrets.h` 里设好真实值。

目前不在防护范围内：WiFi 配网门户的热点（`C3-AdBlock-XXXX`）按设计仍是开放的（不加密）——毕竟得让人在不知道密码的情况下先连进来。你在门户里输入的真实 WiFi 密码，在那一小段配网窗口里，安全性也就等同于这条本地无线电链路。

## 用法

把某个设备的 DNS 指向 C3 的 IP，或者把它作为主 DNS 后面的**辅助解析器**。测试：

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  （被屏蔽）
dig @<c3-ip> github.com        # -> 真实 IP  （被转发）
```

## 已完成 / 后续可以怎么长

- ✅ Web 仪表盘——按客户端统计屏蔽/放行次数，封禁客户端，添加自定义域名
- ✅ mDNS（`c3adblock.local`）自动发现
- ✅ OTA——固件 + 屏蔽列表走 WiFi 更新，外加定时远程拉取屏蔽列表
- ✅ 强制门户配网（不用硬编码凭据）+ 网页一键安装器
- ⬜ 分桶前缀索引——每次查找从约 18 次闪存读取降到约 1–2 次（issue #3），吞吐量的大头
- ⬜ 兼任 DHCP 服务器（把自己作为 DNS 下发出去），做到真正即插即用

## 致谢

灵感来自 [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker)——“对屏蔽列表里的域名回 0.0.0.0”这个思路。本项目是独立从零实现的版本，重点放在无 PSRAM 芯片上的闪存哈希优化。

## 许可证

MIT——见 [LICENSE](LICENSE)。