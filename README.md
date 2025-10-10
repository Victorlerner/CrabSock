# CrabSock

Cross-platform Shadowsocks client (Tauri + Vue 3 + Tailwind).

## Dev

1) Install deps:

```bash
npm install
# if tauri deps are missing
npm install -D @tauri-apps/cli
```

2) Run Tauri dev:

```bash
npm run tauri:dev
```

Requires `sslocal` available in PATH.

### Install Tauri scaffolder (cargo)

```bash
cargo install create-tauri-app --locked
```

Usage example:

```bash
cargo create-tauri-app my-app
```

## Build

```bash
npm run tauri:build
```

env GDK_BACKEND=x11 \
    DISPLAY=$DISPLAY \
    XAUTHORITY=$XAUTHORITY \
    WEBKIT_DISABLE_COMPOSITING_MODE=1 \
    WEBKIT_DISABLE_SANDBOX=1 \
    npm run tauri:dev


pkill -f "tauri dev" || true && pkill -f "vite" || true