# Installation

## From crates.io

```
cargo install petriage
```

## Build from source (CLI only)

```
git clone https://github.com/uky007/petriage.git
cd petriage
cargo build --release
```

The binary will be at `target/release/petriage`.

## Build with TUI Hex Viewer

```
cargo build --release --features tui
```

## Build with GUI

```
cargo build --release --features gui
```

GUI requires system libraries for the graphics backend (OpenGL/Vulkan). On Debian/Ubuntu:

```
sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libgtk-3-dev
```

## Cross-compilation

```
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-gnu
```
