# dt-proxy-server (Rust)

[![Release](https://github.com/digennarot/dt-proxy-server-rs/actions/workflows/release.yml/badge.svg)](https://github.com/digennarot/dt-proxy-server-rs/actions/workflows/release.yml)

A self-hosted, authenticated proxy between the **Deep Translate** module of [Foundry VTT](https://foundryvtt.com) and the
**DeepL API**. Your DeepL key stays on the server; Foundry only ever holds a revocable proxy token.

This is a from-scratch Rust rewrite of [`YanKlInnomme/dt-proxy-server`](https://github.com/YanKlInnomme/dt-proxy-server)
(Node.js, MIT). It is a single native binary (Rust edition 2021, built with `cargo`) and ships as a **Debian package that
installs a hardened systemd service**. No Docker or containers are involved anywhere.

* [Install the .deb package](#1-install-the-deb-package-debian-ubuntu)
* [First start](#2-first-start)
* [Configure the proxy](#3-configure-the-proxy-etcdt-proxy-server)
* [Manage the service](#4-manage-the-service-systemctl-and-journalctl)
* [Connect Foundry VTT](#5-connect-foundry-vtt)
* [Update and uninstall](#6-update-and-uninstall)
* [Build from source](#7-build-from-source) · [Releasing](#8-publishing-a-release-maintainers) · [Reference](#9-reference)

---

## 1. Install the .deb package (Debian, Ubuntu)

Pre-built packages are published on the
[**Releases page**](https://github.com/digennarot/dt-proxy-server-rs/releases) for **`amd64`** (x86_64) and **`arm64`**
(aarch64: Raspberry Pi 4/5 with a 64-bit OS, AWS Graviton, Ampere…), on Linux with glibc ≥ 2.34 (Debian 12, Ubuntu 22.04 and newer).

1. **Find the latest version** on the Releases page and note its tag (for example `v0.1.0`).
2. **Download the package and the checksum file**:

   ```bash
   VERSION=0.1.0                      # replace with the version you want
   ARCH="$(dpkg --print-architecture)"  # amd64 or arm64, detected automatically
   cd /tmp
   wget "https://github.com/digennarot/dt-proxy-server-rs/releases/download/v${VERSION}/dt-proxy-server_${VERSION}-1_${ARCH}.deb"
   wget "https://github.com/digennarot/dt-proxy-server-rs/releases/download/v${VERSION}/SHA256SUMS"
   ```

3. **Verify the download** (it must print `OK` for your `.deb`; `--ignore-missing` skips the other architecture's files):

   ```bash
   sha256sum --ignore-missing -c SHA256SUMS
   ```

4. **Install it.** `apt` resolves the dependencies (`adduser`, `libc6`) for you:

   ```bash
   sudo apt install "./dt-proxy-server_${VERSION}-1_${ARCH}.deb"
   ```

The installation:

* puts the program in `/usr/bin/dt-proxy-server`;
* creates the unprivileged system user `dt-proxy` (no login shell, no home directory);
* installs the configuration in `/etc/dt-proxy-server/` (`config.json` and `dt-proxy-server.env`);
* installs `dt-proxy-server.service` and **enables and starts it automatically**, so the proxy is already running when
  `apt` returns.

Check it:

```bash
systemctl status dt-proxy-server
curl -s http://127.0.0.1:3001/health
```

> A bare binary per architecture (`dt-proxy-server-vX.Y.Z-x86_64-unknown-linux-gnu`, `…-aarch64-unknown-linux-gnu`) is attached to each release as well, for systems
> without `dpkg`. The `.deb` is the recommended way: it brings the service, the user and the config directory.

---

## 2. First start

On a fresh install no DeepL key is configured yet, so the proxy starts in **setup mode**: every route answers `503`
except `/health` and the one-time setup page. Choose **one** of the two ways below.

### Option A – browser setup (recommended)

1. Show the one-time setup URL that the service printed to its log:

   ```bash
   sudo journalctl -u dt-proxy-server -n 50 --no-pager | grep -A2 "one-time setup URL"
   ```

   It looks like `http://localhost:3001/setup?token=…`. The token changes at every restart of the service.
2. Open that URL in a browser **on the same machine**. If the proxy runs on a remote server, forward the port first and
   then open the URL on your own computer:

   ```bash
   ssh -L 3001:127.0.0.1:3001 user@your-server
   ```
3. Paste your DeepL API key and press **Configure proxy**. The key is checked against DeepL, then stored in
   `/etc/dt-proxy-server/secrets.json` (mode `0600`, owned by `dt-proxy`). The page shows the **connection string** for
   Foundry; the `/setup` page then disappears for good.

### Option B – key in the environment file (headless)

```bash
sudo nano /etc/dt-proxy-server/dt-proxy-server.env      # uncomment and fill in DEEPL_API_KEY=...
sudo systemctl restart dt-proxy-server
```

A key supplied this way is read from the environment and is **never written to disk** by the proxy.

---

## 3. Configure the proxy (`/etc/dt-proxy-server/`)

| File | Purpose |
|---|---|
| `/etc/dt-proxy-server/config.json` | Non-secret settings (network, origins, rate limits, TLS). Owned by `dt-proxy`, mode `0600`. |
| `/etc/dt-proxy-server/dt-proxy-server.env` | Optional overrides as `NAME=value` lines (service `EnvironmentFile`), with every option documented in comments. Owned by `root`, mode `0600`. |
| `/etc/dt-proxy-server/secrets.json` | Created by the setup: DeepL key (unless supplied via the env file), proxy token, account id. **Never edit or share it.** |

> **Why JSON, not TOML?** `config.json` is the file format of the original dt-proxy-server (same keys, same names), so
> existing configurations carry over unchanged. Because JSON has no comments, every option is explained in the `.env`
> file. Values in the `.env` file **override** `config.json`.

Step by step:

1. **Optional: make a backup** (`dpkg` keeps your edits on upgrade, but a copy is cheap):

   ```bash
   sudo cp -a /etc/dt-proxy-server /root/dt-proxy-server.backup
   ```
2. **Edit the file you need.** Either:

   ```bash
   sudo nano /etc/dt-proxy-server/dt-proxy-server.env     # simple overrides, commented
   sudo nano /etc/dt-proxy-server/config.json             # full settings
   ```

   Keep `config.json` valid JSON (double quotes, no trailing commas). The service user owns the file because the proxy
   itself rewrites it when it learns the first Foundry origin (remote mode).
3. **Restart** so the change takes effect, then check that it came up:

   ```bash
   sudo systemctl restart dt-proxy-server
   systemctl is-active dt-proxy-server
   sudo journalctl -u dt-proxy-server -n 20 --no-pager
   ```

   If the file is invalid the service refuses to start and the log says which setting is wrong.

### Common setups

**Default – only this computer (nothing to change).** Listens on `127.0.0.1:3001`; only Foundry origins on
`localhost` / `127.0.0.1` are accepted.

**Change the port.** In the `.env` file: `PORT=3100` (or `"port": 3100` in `config.json`), then restart.

**Foundry on another machine in your LAN (trusted network only).** Listening outside loopback is refused unless you name
the exact Foundry origin and explicitly accept plain HTTP:

```ini
HOST=192.168.1.10
ALLOWED_ORIGINS=http://192.168.1.20:30000
DT_PROXY_ALLOW_INSECURE_NETWORK=true
```

**Public server behind an HTTPS reverse proxy (remote mode).** Keep the proxy on loopback and let nginx/Caddy terminate TLS:

```ini
DT_PROXY_MODE=remote
DT_PROXY_PUBLIC_URL=https://translate.example.com
DT_PROXY_BEHIND_TRUSTED_PROXY=true
DT_PROXY_TRUST_PROXY_HOPS=1
```

Example nginx location (the proxy only listens on `127.0.0.1:3001`):

```nginx
location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;
}
```

In remote mode the first Foundry origin that connects *with the correct token* is learned and saved automatically.

**Direct HTTPS without a reverse proxy.** Copy your certificate and key next to the config (readable by `dt-proxy`) and:

```bash
sudo install -o dt-proxy -g dt-proxy -m 0600 fullchain.pem privkey.pem /etc/dt-proxy-server/
```

```ini
DT_PROXY_TLS_ENABLED=true
DT_PROXY_TLS_CERT=fullchain.pem
DT_PROXY_TLS_KEY=privkey.pem
```

**Rate limits.** `rateLimits` in `config.json` (or `DT_PROXY_RATE_*` in the `.env` file) set the maximum requests per window
and route; `0` disables a limit.

### `config.json` keys

| Key | Default | Meaning |
|---|---|---|
| `deploymentMode` | `"local"` | `local` or `remote` |
| `host`, `port` | `127.0.0.1`, `3001` | listen address |
| `publicUrl` | `""` | public HTTPS URL (remote mode; shown in the connection string) |
| `allowedOrigins` | `[]` | exact Foundry origins; empty = loopback origins only |
| `allowNoOrigin` | `false` | accept non-browser clients that send no `Origin` header |
| `allowInsecureNetwork` | `false` | allow plain HTTP on a non-loopback address |
| `behindTrustedProxy`, `trustProxyHops` | `false`, `0` | TLS handled by your reverse proxy / number of proxy hops |
| `rateLimits` | see file | `windowMs`, `default`, `translate`, `usage`, `languages`, `glossaries` |
| `tls` | disabled | `enabled`, `certificateFile`, `privateKeyFile` |
| `secretsFile` | `"secrets.json"` | secrets file name, relative to `/etc/dt-proxy-server/` |

---

## 4. Manage the service (`systemctl` and `journalctl`)

| Task | Command |
|---|---|
| Status (running? last log lines) | `systemctl status dt-proxy-server` |
| Start | `sudo systemctl start dt-proxy-server` |
| Stop | `sudo systemctl stop dt-proxy-server` |
| Restart (after editing the configuration) | `sudo systemctl restart dt-proxy-server` |
| Start automatically at boot (default) | `sudo systemctl enable dt-proxy-server` |
| Do not start at boot | `sudo systemctl disable dt-proxy-server` |
| Enable **and** start now | `sudo systemctl enable --now dt-proxy-server` |
| Is it running? (script-friendly) | `systemctl is-active dt-proxy-server` |
| Follow the log live (Ctrl-C to quit) | `sudo journalctl -u dt-proxy-server -f` |
| Last 100 log lines | `sudo journalctl -u dt-proxy-server -n 100 --no-pager` |
| Log since the last boot | `sudo journalctl -u dt-proxy-server -b` |
| Log of the last hour | `sudo journalctl -u dt-proxy-server --since "1 hour ago"` |
| Errors only | `sudo journalctl -u dt-proxy-server -p err` |

More verbose log: set `RUST_LOG=debug` in the `.env` file and restart (set it back to `info` afterwards).
The service restarts itself after a crash (`Restart=on-failure`, after 5 s).

Troubleshooting:

* **`Unable to listen on …: Address already in use`** – another program uses the port; change `PORT`.
* **`ALLOWED_ORIGINS must contain the exact Foundry origin…`** – you set a non-loopback `HOST`; see the LAN example above.
* **`401` from Foundry** – the token in Foundry is not the proxy's current token; see the next section.
* **Everything answers `503 SETUP_REQUIRED`** – no DeepL key yet; see [First start](#2-first-start).

---

## 5. Connect Foundry VTT

In Foundry, open the Deep Translate module settings and paste the **connection string** (`http://127.0.0.1:3001#dt_…`, or
your public URL followed by `#` and the token). The browser setup page shows it at the end. To display it again:

```bash
sudo bash -c 'set -a; [ -r /etc/dt-proxy-server/dt-proxy-server.env ] && . /etc/dt-proxy-server/dt-proxy-server.env; set +a
  runuser -u dt-proxy -- env DT_PROXY_CONFIG=/etc/dt-proxy-server/config.json dt-proxy-server --show-token'
```

To invalidate the old token (for example if it leaked), use the same command with `--regenerate-token` instead of
`--show-token`, then `sudo systemctl restart dt-proxy-server` and paste the new string into Foundry.

---

## 6. Update and uninstall

**Update:** download the new `.deb` as in step 1 and run `sudo apt install ./dt-proxy-server_<version>-1_$(dpkg --print-architecture).deb`. Your
configuration and secrets are kept (if you edited a config file, `dpkg` asks whether to keep your version: answer **N**,
keep yours), and the service is restarted.

```bash
sudo apt remove dt-proxy-server     # remove the program and the service, KEEP /etc/dt-proxy-server (config + secrets)
sudo apt purge dt-proxy-server      # also delete /etc/dt-proxy-server, /var/lib/dt-proxy-server and the dt-proxy user
```

---

## 7. Build from source

Requires Rust ≥ 1.85 (`rustup`) and a C compiler. Native build, managed only with `cargo`:

```bash
git clone https://github.com/digennarot/dt-proxy-server-rs.git && cd dt-proxy-server-rs
cargo test                 # 114 tests, using an in-process fake DeepL (no network needed)
cargo build --release      # target/release/dt-proxy-server
cargo run --release        # first run: prints the one-time setup URL
```

Build the Debian package yourself:

```bash
cargo install cargo-deb --locked
cargo build --release && cargo deb --no-build     # target/debian/dt-proxy-server_<version>-1_<arch>.deb
```

When run by hand the proxy reads the same settings: environment variables, plus `./deep-translate-proxy-config.json` (or
the file named by `DT_PROXY_CONFIG`). Flags: `--port=N`, `--show-token`, `--regenerate-token`, `--start`, `--version`, `--help`.

---

## 8. Publishing a release (maintainers)

`.github/workflows/release.yml` runs when a tag `vX.Y.Z` is pushed. It checks that the tag equals the version in
`Cargo.toml`, then, **in parallel for `x86_64-unknown-linux-gnu` (amd64) and `aarch64-unknown-linux-gnu` (arm64)**, runs the
tests, builds the release binary and builds the `.deb` with `cargo-deb`. A final job creates one GitHub Release with these
assets: both `.deb` packages, both binaries and a combined `SHA256SUMS`. The arm64 build runs natively on GitHub's
`ubuntu-22.04-arm` runner, which is free for public repositories (a private repository needs a paid larger runner there). Tags containing a hyphen
(`v1.0.0-rc.1`) are published as pre-releases.

```bash
# 1. bump `version` in Cargo.toml, commit, push
# 2. tag and push:
git tag v0.1.0
git push origin v0.1.0
```

The workflow needs no secrets: it uses the automatic `GITHUB_TOKEN` with `contents: write` permission.

---

## 9. Reference

### How the proxy works

* Foundry calls it with `Authorization: Bearer dt_…` (the token is `dt_` + 43 base64url characters).
* Request pipeline, in order: `/setup` authenticates itself → an unconfigured proxy answers only `/health` → an `Origin`
  header is required (unless `allowNoOrigin`) → origin allow-list (remote mode learns the first Foundry origin when the
  token is right) → CORS pre-flight (no token needed) → constant-time token check → per-route rate limit → handler.
* Routes: `GET /health`, `GET /identity`, `POST /translate`, `GET /usage`, `GET /languages?type=source|target`,
  `GET /glossary-language-pairs`, `GET|POST /glossaries`, `PUT|DELETE /glossaries/:id`, `GET|POST /setup`.
* `/translate` accepts up to 300 texts / 120 000 UTF-16 units, caches results in memory (5 000 entries, 64 MiB), sends only
  missing texts to DeepL in one call (`tag_handling=html`) and allows 5 concurrent upstream calls.
* DeepL errors map to `401 DEEPL_AUTH_FAILED`, `429 DEEPL_QUOTA_EXCEEDED` / `DEEPL_RATE_LIMITED`,
  `404 GLOSSARY_NOT_FOUND`, otherwise `502 DEEPL_SERVICE_ERROR`; the `deepl-node` retry policy is reproduced.

### Source layout

```
Cargo.toml                       crate + [package.metadata.deb]
src/main.rs                      CLI, startup, graceful shutdown
src/config.rs                    settings, env vars, secrets files, setup logic      (runtime-config.js)
src/middleware.rs                origin / CORS / token / rate-limit pipeline
src/routes.rs                    API handlers
src/setup_routes.rs, setup_ui.rs first-run browser assistant                         (setup-ui.js)
src/deepl.rs                     DeepL client with retries and error mapping         (deepl-node)
src/glossary.rs, rate_limit.rs, state.rs, server.rs (TLS), error.rs, util.rs
tests/                           integration tests against a fake DeepL
debian/                          service unit, default config, env file, maintainer scripts
.github/workflows/release.yml    tag → test → build → .deb → GitHub Release
```

### Environment variables

| Variable | Meaning |
|---|---|
| `DEEPL_API_KEY` | DeepL key (never persisted when set) |
| `DT_PROXY_TOKEN` | fixed proxy token (never persisted when set) |
| `DT_PROXY_MODE` | `local` (default) or `remote` |
| `PORT`, `HOST` | listen port (3001) / address (127.0.0.1) |
| `ALLOWED_ORIGINS` | comma-separated Foundry origins |
| `DT_PROXY_PUBLIC_URL` | public URL shown in the connection string |
| `DT_PROXY_CONFIG`, `DT_PROXY_SECRETS` | paths of the JSON files (the service sets `DT_PROXY_CONFIG`) |
| `DT_PROXY_TLS_ENABLED`, `DT_PROXY_TLS_CERT`, `DT_PROXY_TLS_KEY` | direct HTTPS with PEM files |
| `DT_PROXY_BEHIND_TRUSTED_PROXY`, `DT_PROXY_TRUST_PROXY_HOPS` | TLS terminated by your reverse proxy |
| `DT_PROXY_ALLOW_INSECURE_NETWORK`, `DT_PROXY_ALLOW_NO_ORIGIN` | explicit opt-outs of safety checks |
| `DT_PROXY_RATE_{TRANSLATE,USAGE,LANGUAGES,GLOSSARIES,DEFAULT,WINDOW_MS}` | rate limits (0 disables) |
| `DT_PROXY_DEEPL_API_URL` | *extension*: alternative DeepL base URL for testing (https, or http on localhost) |
| `RUST_LOG` | log filter (`error`, `warn`, `info`, `debug`) |

### Differences from the original

* Config files default to the current directory (the service uses `/etc/dt-proxy-server`); Docker wording removed.
* Hardening beyond the original: connection cap (512); cache bounded to 64 MiB; secrets written through an unpredictable
  `create_new` temp file; a failed first-run setup leaves config and secrets untouched; `Debug` output redacts secrets; DeepL
  redirects are not followed; `/health` of an exposed proxy returns only `status` and `tls`; the service runs as an unprivileged
  user under systemd sandboxing.
* Original quirks kept: `target_lang` `EN`/`PT` or empty text → 502; control characters in glossary terms → 502; DeepL 400 → 502;
  unknown glossary during translate → 502. Not replicated: Express case-insensitive / trailing-slash routing and automatic ETags.

## License

MIT – see [LICENSE](LICENSE). Original work © 2026 YanK; Rust port by digennarot.
