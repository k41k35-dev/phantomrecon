# 🛡️ Hardening & Portability Notes

**Scope:** Unified Reconnaissance Suite (`nmap_engine.py`, `ferodir.sh`, `web_inspector.py`)

These notes document the design decisions that keep the suite portable, safe to
run, and free of environment-specific assumptions. They are intended as a
reference for contributors, not as a per-release changelog.

---

## 1. No Hardcoded Environment Paths

All path resolution is dynamic and relative to the executing script. The suite
never embeds absolute developer or machine-specific directories.

- Script location resolves via `Path(__file__).resolve().parent`.
- Output directories come from the `RECON_OUT_DIR` environment variable, falling
  back to a local `./recon_output/` when unset.
- `ferodir.sh` locates SecLists through a candidate-path search
  (`/opt/homebrew`, `/usr/share`, `$HOME/...`) instead of a fixed path, and
  resolves `web_inspector.py` relative to its own location.

## 2. Neutral Attribution & Output Naming

- Banners, panels and User-Agent strings use project identifiers
  (`Phantom Recon`, `PhantomRecon-WebInspector`) rather than operator-specific
  handles.
- Generated artifacts use neutral, predictable names (`web_inspector_*.json`,
  `services.md`, `recon_summary.md`).

## 3. Cross-Platform Portability

- Clipboard integration degrades gracefully across `pbcopy` (macOS),
  `xclip`/`wl-copy` (Linux), and is skipped silently when none is present.
- Terminal spawning prefers `tmux` when active, falls back to a native terminal
  emulator, and finally to headless background logging for CI / headless hosts.
- The suite avoids POSIX-only primitives at import time so it can be inspected
  and run on a wider range of hosts.

## 4. Git Hygiene

An exhaustive `.gitignore` blocks scan dumps, network captures, temporary logs,
wordlists, editor metadata and OS metadata (`.DS_Store`, `._*`) so that raw
offensive artifacts never leak into version control.

---

## 5. Verification

Before packaging, run the static checks:

```bash
python3 -m py_compile bin/nmap_engine.py
python3 -m py_compile bin/web_inspector.py
bash -n bin/ferodir.sh
./phantomrecon doctor
```

All four should exit cleanly.
