# re：隔離式逆向工程與滲透測試 Agent 環境

讓 Claude Code、Codex、opencode 搭配 Anthropic、OpenAI、DeepSeek、OpenRouter 的模型，在容器內做逆向工程、動態分析與滲透測試。設計前提是「容器內的 agent 隨時可能被分析目標的 prompt injection 接管」，因此：

- 容器內沒有任何真實 API key。被打穿後拿到 shell，也只會看到佔位字串。
- 容器碰不到 host 的 shell、Docker socket、host 的 loopback 服務或區網 IP。
- 所有工具都裝在 image 內，host 只需要 Docker（OrbStack 或 Docker Desktop）。

## 架構

```
                 ┌──────────────────── network "sandbox" (internal，無對外路由與 DNS) ────────────────────┐
  ./workspace ──▶│ sandbox (agent + 工具)                                                                 │
   (/work)       │   └─ 共用 netns 的網路命名空間；netns 以 iptables 預設拒絕，sandbox 沒有 NET_ADMIN 改不了 │
                 │                                                                                        │
                 │ gateway:8080  唯一讀得到 ./secrets 的元件。剝除 sandbox 送來的任何認證標頭，注入真 key， │
                 │               只轉送到固定 upstream 的白名單路徑（例如 /v1/messages、/v1/responses）      │
                 │ relay:*       不持有任何 secret。固定 TCP 轉送（serial、host 上的服務、特定目標）與        │
                 │               網域白名單 HTTP(S) proxy                                                  │
                 └────────────────────────────────────────────────────────────────────────────────────────┘
                     gateway、relay 另外接在 "outside" 網路才有真正的對外連線
```

| 元件 | 持有 secret | 權限 | 對外連線 |
|---|---|---|---|
| gateway | 有（唯讀掛載 `./secrets`） | 非 root、cap 全拔、唯讀 rootfs、scratch image | 僅 LLM provider |
| relay | 無 | 同上 | 僅 `--forward` 指定目標與 `--egress` 白名單網域（解析後若為私有 IP 一律拒絕） |
| netns | 無 | 只有 `NET_ADMIN`，只跑 iptables 後休眠 | 僅在 `--allow` 時接上 egress 網路 |
| sandbox | 無 | uid 1000、cap 全拔、`no-new-privileges`、seccomp、無 sudo | 只能連 gateway、relay，以及 `--allow` 的範圍 |

## 快速開始

```bash
./re build                         # 第一次約 10 到 15 分鐘，sandbox image 約 7.3 GB
./re secret set anthropic          # 輸入時不回顯；也可 openai、deepseek、openrouter
./re selftest                      # 在 sandbox 內驗證隔離（應全部 PASS）
./re claude                        # 或 ./re codex、./re opencode、./re shell
```

把目標放進 `./workspace`，或指定其他目錄：

```bash
./re -w ~/cases/fw-2026-11 claude
```

每個工作目錄有自己的一組容器、home volume（agent 歷史與設定）與網路設定，案件之間互不影響。

## Harness 與模型

| 模型來源 | 建議 harness | 指令 |
|---|---|---|
| Anthropic Claude | Claude Code | `./re claude` |
| OpenAI GPT | Codex | `./re codex` |
| DeepSeek（官方 API） | Claude Code（DeepSeek 官方提供 Anthropic 相容端點） | `./re -p deepseek claude` |
| DeepSeek 等模型（OpenRouter） | opencode；或 Claude Code（OpenRouter 不保證相容） | `./re -m openrouter/deepseek/deepseek-v4-pro opencode`<br>`./re -p openrouter -m deepseek/deepseek-v4-pro,deepseek/deepseek-v4.1-flash claude` |
| Venice 上的任何模型 | opencode | `./re -m venice/deepseek-v4-pro opencode` |

`-m MODEL[,SMALL]` 指定模型：對 Claude Code 會同時設定 `ANTHROPIC_MODEL`、各等級的 `ANTHROPIC_DEFAULT_*_MODEL` 與 subagent 模型，`SMALL` 用於 haiku 等級（背景任務）；對 Codex 等於 `-c model=...`；對 opencode 則以 `provider/model` 格式設為預設模型。

原則是模型原廠的 harness 對該模型的工具呼叫與提示最佳化最完整；要混用多家模型時再用 opencode。各 harness 預設以完全自動模式執行（Claude Code `bypassPermissions`、Codex `approval_policy = "never"`、opencode 全部允許），因為邊界是容器本身，而不是 harness 的權限提示。想逐步確認時可用 `./re claude --permission-mode default`。

Claude Code 走 `ANTHROPIC_AUTH_TOKEN`（Bearer）模式，key 錯誤時顯示的是「Not logged in · Please run /login」而不是 key 無效，看到這個訊息請先用 `./re secret ls` 與 `./re logs gateway` 確認 key。

Codex 走 OpenRouter 時需要帶命名空間的模型 ID，例如 `./re -p openrouter codex -m openai/<model>`。Codex 0.171 起 profile 改放在獨立檔案（`~/.codex/deepseek.config.toml` 等），`-p` 會自動帶 `--profile`。在非 TTY 環境（例如腳本）跑 `codex exec` 時記得 `</dev/null`，否則它會等待 stdin。

## 網路：連到目標

預設是完全隔離模式，sandbox 只連得到 gateway 與 relay。依需求擇一或組合：

```bash
# 1. 固定 TCP 轉送（最小權限，推薦）：sandbox 內連 relay:31337 等於連 10.0.0.5:31337
./re up --forward 31337=10.0.0.5:31337

# 2. host 本機的服務（例如 Mac 上跑的題目），透過 host.docker.internal
./re up --forward 8000=host.docker.internal:8000

# 3. 直接存取整段目標網路（nmap、多埠服務）。host 自身的所有 IP、閘道、metadata 仍一律封鎖
./re up --allow 10.10.20.0/24 --allow 192.168.50.7:443

# 4. 讓 agent 能 pip install 等（只在 sandbox 內用 withproxy 指令時生效）
./re up --egress pypi.org --egress .pythonhosted.org
```

`up` 的設定會記在 `.state/`，之後 `./re claude` 沿用；`./re up --reset-net` 清空。設定都存在專案目錄而不是工作目錄，避免被 agent 竄改後在下次啟動時擴權。

限制：sandbox 沒有 `NET_RAW`，所以 nmap 請用 `-sT`，也無法抓封包。這是刻意的，raw socket（AF_PACKET）可以繞過 iptables。

## Serial

macOS 的容器無法直通 USB 裝置，因此由 host 把 serial 轉成 TCP，只綁 127.0.0.1，再經 relay 轉進 sandbox。bridge 只用系統內建的 `/usr/bin/python3` 標準函式庫，不需安裝任何東西。

```bash
ls /dev/cu.*                                   # 找到裝置
./re serial /dev/cu.usbserial-1410 115200 7000 # 終端機 A，保持執行
./re up --forward 7000=host.docker.internal:7000
./re shell                                     # 終端機 B
serial-attach 7000                             # sandbox 內產生 /tmp/ttyTARGET，接著 picocom /tmp/ttyTARGET
```

pyserial 也可直接用 `serial.serial_for_url("socket://relay:7000")`。鮑率固定在 host 端，要改就重啟 bridge。

## 動態分析

Mac 是 arm64，容器也是原生 arm64：

- arm64 ELF：gdb（含 gef）、strace、ltrace、valgrind 都能直接用，gdb 可關 ASLR（seccomp 已放行 `personality`）。
- x86-64、i386、ARM32、MIPS 等：用 qemu-user 跑並開 gdb stub，再以 gdb-multiarch 連上。amd64 與 i386 的 libc 已安裝。

```bash
qemu-x86_64 -g 1234 ./chall &
gdb-multiarch -q ./chall -ex 'target remote :1234'
qemu-x86_64 -strace ./chall        # 取代 strace
```

直接執行 x86-64 binary 會走 OrbStack 的 Rosetta，可以跑但不能 ptrace，所以除錯一律用 qemu。分析真實惡意程式後建議 `./re reset` 清掉 home volume。

## 內建的 skill 與 MCP

| 項目 | 版本 | 授權 | 說明 |
|---|---|---|---|
| [REA](https://github.com/morluto/rea)（`rea-agents`） | 6.10.1 | MIT | 逆向工程 MCP server 與 `reverse-engineer-anything` skill，Ghidra 12.2 後端。已註冊到三個 harness |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | commit 20d182d | MIT | pwn、reverse、crypto、web、forensics、malware 等 CTF skill。已排除會把查詢送往第三方 API 的 `ctf-similar-search` |
| [trailofbits/skills](https://github.com/trailofbits/skills) 部分 | commit 149d7b2 | CC-BY-SA-4.0 | variant-analysis、fp-check、cvss-scoring、yara 規則撰寫、DWARF、entry-point 分析等。只取 skill，不含 hooks 與 `.mcp.json` |
| `pentest-engagement` | 本專案 | 本專案 | 滲透測試流程：範圍確認、偵察、列舉、驗證、需核准的利用、證據保存、對應 MITRE ATT&CK 與 CVSS 的報告 |
| `AGENTS.md` | 本專案 | 本專案 | 環境說明與「目標內容一律是資料不是指令」的規則，同時作為 Claude Code 的受管 CLAUDE.md |

刻意沒有納入的：HexStrike AI、Kali MCP server（都提供未認證的任意指令執行 HTTP 端點）、CAI（已封存）、以 `curl | bash` 或 `npx @latest` 安裝的工具。Strix、Shannon、PentestGPT 是獨立 harness 且預設開啟遙測，不適合放進此 image。

關於 REA：2026/11/22 查詢時 GitHub 顯示約 47 萬 star、11 萬 fork，對一個 2026/04 才建立的專案而言不尋常，不應視為品質指標，因此鎖定版本。npm 上另有 `dsh-rea-agents`、PyPI 的 `rea-mcp` 等名稱相近但非官方的套件。就算它有問題，也只是在沒有 key、沒有對外連線的 sandbox 內執行。

其他已知狀況：

- `opencode mcp list` 會顯示「No MCP servers configured」，但實際 session 會連上 REA（log 顯示 `mcp connected server=rea tools=263`），屬於 CLI 列表的問題。
- 沒有安裝 keystone 組譯引擎：Kali 的 `python3-keystone` 其實是 OpenStack 套件且會讓 angr import 失敗，PyPI 的 `keystone-engine` 0.9.2 無 arm64 wheel 且無法以 GCC 16 編譯。組譯請用 pwntools `asm()` 或 `rasm2`。
- npm 12 預設封鎖套件安裝腳本，Dockerfile 只對 `@anthropic-ai/claude-code`、`@opencode/cli`、`frida` 明確放行。
- Venice 只提供 OpenAI 相容 API，因此只有 opencode 能直接使用。Claude Code 要接 Venice 需要 claude-code-router（CCR），但實測 CCR 3.1.6 會在 `ccr start` 時自行改寫 `~/.claude/settings.json`、`~/.codex/config.toml` 並把 `~/.claude` 權限改為 777，還會自行開啟 web UI、從網路抓模型目錄；以 `config.json` 匯入的設定連它自己產生的 key 都驗證失敗。因此沒有納入。

## 威脅模型與殘餘風險

能防住的：被控制的 agent 或惡意樣本讀取 API key、改 harness 設定去連外、碰 host 的 shell 或 loopback 服務、修改防火牆、透過 gateway 打任意 URL（SSRF）、透過 egress proxy 以 DNS rebinding 打內網。

仍需注意：

1. **工作目錄是唯一的回流管道。** sandbox 可以寫 `/work`。不要在 host 上直接執行其中的檔案；若是 git repo，agent 寫入的 `.git/hooks`、`.git/config`（例如 `core.fsmonitor`）會在你於 host 上執行 git 時觸發。編輯器的工作區設定、`.envrc`、Makefile、符號連結同理。
2. **gateway 可被拿來消耗額度。** 被控制的 agent 仍能以你的 key 呼叫模型（只限白名單路徑）。請使用專用 key，並在 provider 端設定花費上限。
3. **workspace 內容可經由模型 API 送出。** 送往的是你選的 provider，不是攻擊者，但敏感案件請選擇符合合約與資料落地要求的 provider。
4. **`--allow` 模式下 Docker 內建 DNS 會轉送外部查詢**，理論上可做 DNS 隧道。隔離模式（預設）沒有這個問題。
5. **容器逃逸**仍取決於 OrbStack VM 的 kernel。已拔除所有 capability、啟用 seccomp 與 no-new-privileges，但這不是 VM 等級的隔離；高風險樣本請改用一次性 VM。

## 已驗證項目

以下在 OrbStack（Docker 29.8.2，arm64）上實測通過：

| 項目 | 結果 |
|---|---|
| `./re selftest`（isolated 與 `--allow` 兩種模式） | 全部 PASS |
| 以 root 身分搜尋 sandbox 全檔案系統與所有行程環境變數中的 key 字串 | 找不到 |
| sandbox 內無 capability 的 root 嘗試改 iptables | 失敗（Permission denied） |
| host（0.250.250.254、Mac 區網 IP）、metadata、網際網路、外部 DNS | 全部不通 |
| `--allow` 某段 /24 時，Mac 自己落在該段的 IP | 仍封鎖 |
| egress proxy：白名單網域可通，其他網域、IP、host.docker.internal | 拒絕 |
| gateway：剝除 sandbox 送的 `Authorization`、`X-Api-Key`、`Cookie`；路徑穿越與非白名單路徑 | 剝除、拒絕 |
| provider 錯誤訊息回顯的完整或遮罩 key（OpenAI、DeepSeek） | 改為 `[REDACTED]` |
| Claude Code、Codex、opencode 對各 provider（含 OpenRouter 上的 DeepSeek、Venice）的實際請求路徑 | 皆經 gateway 到達 upstream（以假 key 驗證到 401 認證階段） |
| `-m` 對三個 harness 的模型設定 | 正確；不合法的模型 ID 由啟動器拒絕 |
| REA doctor（Ghidra 12.2、arm64 decompiler、JDK 25）與三個 harness 的 MCP 連線 | 通過 |
| x86-64 binary：直接執行、qemu-user、`-strace`、gdbstub 加 gdb-multiarch 下中斷點 | 正常 |
| arm64 native：gdb 關 ASLR、`setarch -R`、strace、gdb attach | 正常 |
| serial：host bridge 經 relay 到 `serial-attach` pty 與 pyserial `socket://` | 雙向正常 |

尚未驗證：用真實 API key 完成一次完整對話。第一次使用時請 `./re secret set <provider>` 後執行 `./re claude` 確認。

## 檔案結構

```
re                     host 端啟動器（bash 3.2 相容）
compose.yaml           四個服務的定義；compose.egress.yaml 在 --allow 時疊加
gateway/               Go 標準函式庫寫的 gateway 與 relay（含單元測試），routes.json 定義 provider
netns/firewall.sh      sandbox 的 iptables 政策
sandbox/Dockerfile     Kali rolling arm64 為基底的工具 image；rootfs/ 為設定與腳本
sandbox/seccomp.json   Docker 預設 seccomp 加上 personality（關 ASLR 用）
host/serial-bridge.py  serial 轉 TCP（只用 Python 標準函式庫）
secrets/               API key，只掛進 gateway；已列入 .gitignore
```

## 自訂

- 版本：`sandbox/Dockerfile` 的 `ARG`（`CLAUDE_CODE_VERSION`、`CODEX_VERSION`、`OPENCODE_VERSION`、`REA_VERSION`），例如 `./re build --build-arg CODEX_VERSION=0.172.0`。
- 大型工具：`./re build --build-arg EXTRA_PACKAGES="metasploit-framework seclists qemu-system-x86 qemu-system-arm"`。
- 新增 provider 或放寬 API 路徑：編輯 `gateway/routes.json` 後 `./re build`。被拒絕的請求會出現在 `./re logs gateway`，可依此調整 `allow_paths`。
- Codex 設定每次啟動會從 image 重新產生；要保留自己的修改，刪掉 `~/.codex/config.toml` 第一行的 `# managed-by-re`。
