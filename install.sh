#!/bin/sh
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BIN_TARGET="/usr/local/bin/lopata"
THIRD_PARTY="$REPO_DIR/third_party"
INSTALL_TOOLS=1
APK_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --no-tools) INSTALL_TOOLS=0 ;;
        --apk-only) APK_ONLY=1 ;;
        -h|--help)
            echo "Usage: $0 [--no-tools] [--apk-only]"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

say()  { printf '\033[36m[lopata]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[lopata]\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m[lopata]\033[0m %s\n' "$1"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v doas >/dev/null 2>&1; then SUDO="doas";
    elif command -v sudo >/dev/null 2>&1; then SUDO="sudo";
    else warn "not root and no doas/sudo found; apk + symlink steps will fail."; fi
else
    warn "Running as root: the venv will be root-owned. Prefer running as your"
    warn "normal user so the venv stays yours (the script escalates per-step)."
fi

symlink() {
    [ -x "$1" ] || return 1
    $SUDO ln -sf "$1" "/usr/local/bin/$2"
}

# go_install <module@version> <binname>: build a Go tool and symlink it into
# /usr/local/bin so lopata's runtime detection finds it.
go_install() {
    command -v "$2" >/dev/null 2>&1 && { ok "$2 already present"; return 0; }
    command -v go >/dev/null 2>&1 || $SUDO apk add --no-cache go
    if ! command -v go >/dev/null 2>&1; then
        warn "Go unavailable; skipping $2."; return 1
    fi
    say "Installing $2 (via Go; first build can take a minute)..."
    if GO111MODULE=on go install "$1"; then
        gobin="$(go env GOBIN)"; [ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
        symlink "$gobin/$2" "$2" && ok "$2 -> /usr/local/bin/$2" \
            || warn "$2 built but symlink failed."
    else
        warn "$2 build failed; that tool will skip at runtime."
    fi
}

say "Installing base packages via apk..."
$SUDO apk add --no-cache \
    python3 py3-pip python3-dev \
    gcc musl-dev libffi-dev openssl-dev \
    freetype-dev jpeg-dev zlib-dev \
    git curl \
    || warn "apk base package step reported an error; continuing."

if [ "$INSTALL_TOOLS" -eq 1 ]; then
    set +e

    say "Installing apk-packaged tools (nmap, nikto + perl deps)..."
    $SUDO apk add --no-cache nmap nmap-scripts nikto \
        perl perl-xml-writer perl-json \
        perl-net-ssleay perl-crypt-ssleay perl-io-socket-ssl \
        && ok "nmap + nikto installed" \
        || warn "nmap/nikto install had errors; those modules will skip."
    [ -x /usr/bin/nikto.pl ] && symlink /usr/bin/nikto.pl nikto

    say "Installing apk-packaged tools (sqlmap, gitleaks — community repo)..."
    $SUDO apk add --no-cache sqlmap gitleaks \
        && ok "sqlmap + gitleaks installed" \
        || warn "sqlmap/gitleaks not found in apk; enable the community repo or "
    warn "install them manually (pip install sqlmap / go install gitleaks)."

    if [ "$APK_ONLY" -eq 0 ]; then
        mkdir -p "$THIRD_PARTY"

        if command -v subfinder >/dev/null 2>&1; then
            ok "subfinder already present"
        else
            say "Installing subfinder (via Go; first build can take a minute)..."
            command -v go >/dev/null 2>&1 || $SUDO apk add --no-cache go
            if command -v go >/dev/null 2>&1; then
                GO111MODULE=on go install \
                    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                gobin="$(go env GOBIN)"
                [ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
                if symlink "$gobin/subfinder" subfinder; then
                    ok "subfinder installed -> /usr/local/bin/subfinder"
                else
                    warn "subfinder build failed; subdomain module will skip."
                fi
            else
                warn "Go unavailable; skipping subfinder."
            fi
        fi

        # ProjectDiscovery + Dalfox + ffuf: all Go, all not in apk.
        go_install github.com/projectdiscovery/httpx/cmd/httpx@latest httpx
        go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
        go_install github.com/hahwul/dalfox/v2@latest dalfox
        go_install github.com/ffuf/ffuf/v2@latest ffuf
        if command -v nuclei >/dev/null 2>&1; then
            say "Fetching nuclei templates (one-off; scans run with -duc after)..."
            nuclei -update-templates >/dev/null 2>&1 \
                && ok "nuclei templates installed" \
                || warn "nuclei template fetch failed; run 'nuclei -update-templates'."
        fi

        if command -v whatweb >/dev/null 2>&1; then
            ok "whatweb already present"
        else
            say "Installing whatweb (git clone + Ruby deps)..."
            $SUDO apk add --no-cache ruby ruby-dev
            if command -v gem >/dev/null 2>&1; then
                if [ -d "$THIRD_PARTY/whatweb/.git" ]; then
                    git -C "$THIRD_PARTY/whatweb" pull --quiet
                else
                    git clone --depth 1 \
                        https://github.com/urbanadventurer/WhatWeb \
                        "$THIRD_PARTY/whatweb"
                fi
                $SUDO gem install --no-document \
                    getoptlong resolv resolv-replace ipaddr addressable json
                if [ -f "$THIRD_PARTY/whatweb/whatweb" ]; then
                    $SUDO tee /usr/local/bin/whatweb >/dev/null <<EOF
#!/bin/sh
exec ruby "$THIRD_PARTY/whatweb/whatweb" "\$@"
EOF
                    $SUDO chmod +x /usr/local/bin/whatweb
                fi
                command -v whatweb >/dev/null 2>&1 \
                    && ok "whatweb installed -> /usr/local/bin/whatweb" \
                    || warn "whatweb setup failed; fingerprint module will skip."
            else
                warn "RubyGems unavailable; skipping whatweb."
            fi
        fi

        if command -v testssl.sh >/dev/null 2>&1; then
            ok "testssl.sh already present"
        else
            say "Fetching testssl.sh (TLS fallback for when sslyze is absent)..."
            if [ -d "$THIRD_PARTY/testssl.sh/.git" ]; then
                git -C "$THIRD_PARTY/testssl.sh" pull --quiet
            else
                git clone --depth 1 https://github.com/drwetter/testssl.sh \
                    "$THIRD_PARTY/testssl.sh"
            fi
            symlink "$THIRD_PARTY/testssl.sh/testssl.sh" testssl.sh \
                && ok "testssl.sh installed" \
                || warn "testssl.sh fetch failed; sslyze still covers TLS checks."
        fi
    fi

    set -e
else
    warn "Skipping external tools (--no-tools). Web-layer modules only."
fi

say "Creating virtualenv at $VENV_DIR ..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip wheel >/dev/null
say "Installing lopata and Python dependencies..."
"$VENV_DIR/bin/pip" install -e "$REPO_DIR"

if [ "$INSTALL_TOOLS" -eq 1 ]; then
    say "Installing sslyze (TLS/SSL engine) into the venv..."
    "$VENV_DIR/bin/pip" install sslyze \
        && ok "sslyze installed" \
        || warn "sslyze install failed; install testssl.sh (done above) for TLS."

    say "Installing arjun (hidden-parameter discovery) into the venv..."
    if "$VENV_DIR/bin/pip" install arjun; then
        symlink "$VENV_DIR/bin/arjun" arjun
        ok "arjun installed"
    else
        warn "arjun install failed; hidden-parameter discovery will skip."
    fi
fi

say "Linking launcher -> $BIN_TARGET"
$SUDO rm -f "$BIN_TARGET"
$SUDO tee "$BIN_TARGET" >/dev/null <<EOF
#!/bin/sh
exec "$VENV_DIR/bin/lopata" "\$@"
EOF
$SUDO chmod +x "$BIN_TARGET"

echo
ok "Install complete. Detected external tools:"
for t in nmap nikto subfinder whatweb testssl.sh httpx ffuf nuclei dalfox \
         sqlmap gitleaks; do
    if command -v "$t" >/dev/null 2>&1; then
        printf '  \033[32m OK\033[0m %s\n' "$t"
    else
        printf '  \033[33m --\033[0m %s (absent; tool will skip)\n' "$t"
    fi
done
if [ -x "$VENV_DIR/bin/sslyze" ] || command -v sslyze >/dev/null 2>&1; then
    printf '  \033[32m OK\033[0m sslyze (TLS engine)\n'
else
    printf '  \033[33m --\033[0m sslyze\n'
fi
if [ -x "$VENV_DIR/bin/arjun" ] || command -v arjun >/dev/null 2>&1; then
    printf '  \033[32m OK\033[0m arjun (hidden-parameter discovery)\n'
else
    printf '  \033[33m --\033[0m arjun\n'
fi
printf '  \033[33m ~~\033[0m zap (optional DAST — not auto-installed; start ZAP as a\n'
printf '        daemon and set zap_api/zap_api_key in your profile to enable)\n'
echo
say "Try:  lopata --help"
say "Reminder: only scan systems you are authorized to test."
