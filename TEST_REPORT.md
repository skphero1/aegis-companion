# Aegis Companion — Test Report (18 Nov 2026)

**Name:** Aegis Companion — Sysfortech Shield Windows Companion App, v0.1.0
**What it is:** Phase 2 of Sysfortech Shield (Phase 1 = Link Shield Chrome extension).
Electron 45.3.4 desktop shell: on-demand folder scan + quarantine vault + dashboard.
Zero third-party runtime dependencies beyond Electron; Node built-in `crypto` + `fs/promises` only.
**Location:** `workspace/projects/aegis-companion/`

## Verdict: WORKS as a starter shell — 33/33 functional checks pass, real app launches

It is a working shell, not a real antivirus. The scan engine is placeholder heuristics
(extension list + 1 real EICAR hash). See "Honest limits" — do not sell or demo it as
real-time protection or real malware detection.

## How to run (Windows)

```powershell
mkdir aegis-companion; cd aegis-companion
# save the 6 files here, then:
npm install
npm start
```

Test workflow: make a `scan-test` folder with a harmless `.txt`, an empty `demo.bat` /
`sample.ps1`, and an EICAR test-string file. Scan Folder → quarantine the flagged
file → Quarantine view → Restore, then Delete.

## Tests run (this VM, Linux — same code path as Windows)

### 1. Static checks — all pass
- `node --check` main.js, preload.js, renderer.js — OK
- `package.json` valid JSON; Electron `^45.3.4`, `main: main.js`, `start: electron .`
- All 24 element IDs used by renderer.js exist in index.html (0 missing)
- All 7 IPC channels match between main.js and preload.js:
  `app:get-dashboard`, `app:toggle-protection`, `scan:pick-and-run`,
  `quarantine:add`, `quarantine:list`, `quarantine:restore`, `quarantine:delete`

### 2. Functional test of the real main.js — 33/33 pass
`node tests/test-main-mocked.js` — loads the real main.js with a mocked `electron`
module and drives its real IPC handlers (no GUI needed):
- Test folder (5 files): `harmless.txt`, `demo.bat`, `sample.ps1`, `eicar.txt`
  (exact 68-byte EICAR string, SHA-256 `275a021b…fd0f`), `nested/inner.txt`
- Scan: total 5, flagged 3. `harmless.txt` + `inner.txt` clean; `demo.bat` /
  `sample.ps1` warning ("Suspicious Executable/Script Extension");
  `eicar.txt` **critical** by hash ("Known Bad Hash: EICAR-Test-Signature (Demo)")
  even though `.txt` is not a suspicious extension. Flagged files sort to the top.
- Dashboard: fresh count 0, protection toggle off/on persists, `lastScan` persists.
- Quarantine `demo.bat`: original file moved away, vault holds 1 `*.quarantined`
  file, manifest lists it, dashboard count becomes 1.
- Restore: file returns to its original folder, manifest empties.
- Quarantine again + Delete: vault empties, file is permanently gone (not restored).
- Restore/Delete of an unknown id both throw `Quarantine item not found`.
- preload.js exposes `window.companionAPI` with all 7 methods.

### 3. Real Electron launch — pass
- `npm install`: 13 packages, Electron binary downloaded. `./node_modules/.bin/electron --version --no-sandbox` → **v45.3.4**
- `xvfb-run electron . --no-sandbox`: app stayed alive the full 15 s test window
  (killed by timeout, exit 124 = still running, as expected — no auto-quit).
- DevTools check (`--remote-debugging-port=9222`, `/json/list`): page loaded —
  title `Aegis Companion — Endpoint Scanner`, URL `file:///.../index.html`.
- Only log noise was Linux-VM dbus errors (no system dbus here); no JS exceptions,
  no failed loads. On Windows the `--no-sandbox` flag is not needed.

## Honest limits (found by audit, not by the tests)
1. **Placeholder detection only.** Any `.exe/.bat/.cmd/.ps1/.vbs/.scr/.js/.dll` is
   flagged "warning" — including perfectly legit files. Real malware with a `.txt`
   extension or a new hash is missed unless its hash is in the 1-entry list.
   The second bad hash (`deadbeef000…01`) is a fake that can never match a real file.
2. **No real-time protection.** The "Real-Time Guard Active" toggle is placeholder
   state only — it flips a boolean in `app-state.json`. Nothing watches files.
3. **Quarantine is rename + move, not neutralisation.** Files sit in
   `%APPDATA%\aegis-companion\quarantine_vault` as `<uuid>.quarantined` — no
   encryption. Renaming one back restores it. The UI line "neutralized" overstates it.
4. **Scan cap 300 files; whole-file hashing.** `computeSha256` reads each file fully
   into memory (`fs.readFile`) — a multi-GB file can spike RAM. Stream the hash for v2.
5. **Restore overwrites silently.** If a file reappears at the original path before
   restore, `rename` replaces it. Check-before-restore (or rename-on-conflict) needed.
6. **Quarantined state is in-memory in the renderer** (`quarantinedPaths` set resets
   on reload), so after a restart the Quarantine button re-enables for a file already
   in the vault; clicking it fails with a toast instead of being disabled.
7. **No tests shipped in the pasted project** — the mocked-Electron harness above
   was added here as `tests/test-main-mocked.js` so the run is reproducible.

## Next steps for v0.2 (not done)
- Replace placeholder rules with a real engine (ClamAV / YARA / AMSI) or clearly
  label this a demo shell; stream file hashing; 300-file cap → paged scan.
- Encrypt vault files at rest; confirm-before-restore on path conflict.
- Real-time guard (file watcher) or drop the "Real-Time" wording.
- Windows installer packaging (`electron-builder`, no native build tools needed
  only while no native deps are added) — untested here, Linux VM only.
- Test on real Windows 11, in a test profile/VM only during the post-hack watch week.
