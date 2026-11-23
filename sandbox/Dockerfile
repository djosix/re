# Untrusted side: agent harnesses + RE/pentest tooling. Holds NO credentials.
ARG KALI_IMAGE=kalilinux/kali-rolling:latest

# ---- vendored third-party skills, pinned by commit -------------------------
FROM ${KALI_IMAGE} AS skills
ARG CTF_SKILLS_REF=20d182d9377f0467830f314bb0f843cae4dbf55e
ARG TOB_SKILLS_REF=149d7b21f4067765b82e67029730b42d228ef4b4
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eux; fetch() { mkdir -p "/src/$1"; cd "/src/$1"; git init -q; git fetch -q --depth 1 "$2" "$3"; git checkout -q FETCH_HEAD; }; \
    fetch ctf https://github.com/ljagiello/ctf-skills "$CTF_SKILLS_REF"; \
    fetch tob https://github.com/trailofbits/skills "$TOB_SKILLS_REF"; \
    mkdir -p /out/skills /out/licenses; \
    # ctf-similar-search sends queries to a third-party API: excluded.
    for s in ctf-pwn ctf-reverse ctf-crypto ctf-web ctf-forensics ctf-malware ctf-misc ctf-ai-ml ctf-osint ctf-writeup solve-challenge; do \
      cp -r "/src/ctf/$s" /out/skills/; done; \
    cp /src/ctf/LICENSE /out/licenses/ljagiello-ctf-skills.LICENSE; \
    # Skills only: no hooks, no .mcp.json, no commands.
    for p in variant-analysis fp-check cvss-scoring yara-authoring dwarf-expert vulnerability-triage-brocards entry-point-analyzer firebase-apk-scanner; do \
      cp -r /src/tob/plugins/$p/skills/* /out/skills/; done; \
    cp /src/tob/LICENSE /out/licenses/trailofbits-skills.LICENSE; \
    printf 'ljagiello/ctf-skills %s (MIT)\ntrailofbits/skills %s (CC-BY-SA-4.0)\n' "$CTF_SKILLS_REF" "$TOB_SKILLS_REF" > /out/licenses/SOURCES

# ---- main image -------------------------------------------------------------
FROM ${KALI_IMAGE}
ARG CLAUDE_CODE_VERSION=2.1.330
ARG CODEX_VERSION=0.171.0
ARG OPENCODE_VERSION=2.3.2
ARG REA_VERSION=6.10.1
# e.g. --build-arg EXTRA_PACKAGES="metasploit-framework seclists qemu-system-x86 qemu-system-arm"
ARG EXTRA_PACKAGES=""
ARG WITH_ANGR=1
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN set -eux; dpkg --add-architecture amd64; dpkg --add-architecture i386; apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq ripgrep fd-find tmux vim nano less file xxd bsdextrautils \
      unzip zip p7zip-full xz-utils zstd cpio procps psmisc lsof iproute2 iputils-ping dnsutils \
      netcat-openbsd socat openssl sqlite3 tini \
      build-essential gcc g++ make cmake pkg-config nasm \
      python3 python3-pip python3-venv python3-dev nodejs npm \
      openjdk-25-jdk-headless ghidra radare2 \
      gdb gdb-multiarch gef strace ltrace valgrind binutils-multiarch elfutils patchelf \
      checksec ropper python3-ropgadget python3-pwntools python3-capstone python3-unicorn \
      python3-lief python3-pycryptodome python3-z3 python3-sympy python3-gmpy2 \
      python3-requests binwalk upx-ucl yara qemu-user gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
      libc6:amd64 libstdc++6:amd64 zlib1g:amd64 libc6:i386 jadx apktool \
      nmap sqlmap ffuf gobuster feroxbuster nuclei netexec python3-impacket impacket-scripts \
      hydra john smbclient ldap-utils enum4linux-ng whatweb nikto testssl.sh sslscan wordlists \
      proxychains4 httpie \
      picocom minicom python3-serial \
      $EXTRA_PACKAGES; \
    rm -rf /var/lib/apt/lists/*; \
    ln -sf /usr/bin/fdfind /usr/local/bin/fd

# Python tools not packaged for Kali arm64. System site-packages stay visible.
RUN set -eux; python3 -m venv --system-site-packages /opt/re/venv; \
    /opt/re/venv/bin/pip install --no-cache-dir uv frida-tools; \
    if [ "$WITH_ANGR" = 1 ]; then /opt/re/venv/bin/pip install --no-cache-dir angr \
      || echo "angr: install failed, skipped" >> /opt/re/BUILD_NOTES; fi
# Not installed on purpose: Debian's python3-keystone is OpenStack (it shadows the assembler and breaks
# angr's import), and keystone-engine 0.9.2's bundled LLVM does not build with GCC 16. Use pwntools asm()
# or rasm2 for assembling.

# Agent harnesses + REA, pinned. Installed globally so image upgrades take effect.
# npm 12 blocks install scripts by default; allow only the ones that fetch native binaries.
RUN set -eux; npm install -g --no-fund --no-audit \
      --allow-scripts=@anthropic-ai/claude-code,@opencode/cli,frida \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@openai/codex@${CODEX_VERSION}" \
      "@opencode/cli@${OPENCODE_VERSION}" \
      "rea-agents@${REA_VERSION}"; \
    npm cache clean --force; \
    claude --version; codex --version; opencode --version; rea --version

COPY --from=skills /out/skills/ /opt/re/skills/
COPY --from=skills /out/licenses/ /opt/re/skills/THIRD_PARTY/
COPY rootfs/ /
RUN set -eux; \
    rea_skill=$(dirname "$(find /usr/local/lib/node_modules/rea-agents -path '*reverse-engineer-anything/SKILL.md' | head -n1)"); \
    [ -d "$rea_skill" ] && cp -r "$rea_skill" /opt/re/skills/; \
    mkdir -p /etc/codex; ln -sfn /opt/re/skills /etc/codex/skills; ln -sfn /opt/re/AGENTS.md /etc/claude-code/CLAUDE.md; \
    chmod 0755 /opt/re/bin/*; \
    useradd -m -u 1000 -s /bin/bash re; mkdir -p /work && chown re:re /work; \
    printf 'claude-code %s\ncodex %s\nopencode %s\nrea-agents %s\n' \
      "$CLAUDE_CODE_VERSION" "$CODEX_VERSION" "$OPENCODE_VERSION" "$REA_VERSION" >> /opt/re/VERSIONS

ENV PATH=/opt/re/bin:/opt/re/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    RE_GATEWAY=http://gateway:8080 \
    CODEX_HOME=/home/re/.codex \
    GHIDRA_INSTALL_DIR=/usr/share/ghidra \
    JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64 \
    NO_UPDATE_NOTIFIER=1 \
    OPENCODE_DISABLE_AUTOUPDATE=1 \
    PIP_PROXY=http://relay:3128 \
    npm_config_proxy=http://relay:3128 \
    npm_config_https_proxy=http://relay:3128 \
    PWNLIB_NOTERM=0
USER re
WORKDIR /work
ENTRYPOINT ["/opt/re/bin/re-entrypoint"]
CMD ["sleep", "infinity"]
