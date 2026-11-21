// Functional test of the REAL ../main.js with a mocked 'electron' module
// (no GUI, no Electron binary needed).
// Run:  node tests/test-main-mocked.js
// Tests: dashboard, toggle, scan (clean/warning/critical), quarantine,
// restore, delete, error paths, plus preload.js API surface.
const Module = require('module');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');

const PROJECT = path.resolve(__dirname, '..');
const USER_DATA = '/tmp/aegis-test/userData';
const SCAN_DIR = '/tmp/aegis-test/scan-test';

const handlers = {};
const exposed = {};
let windowsCreated = 0;

const mockElectron = {
  app: {
    getPath: (name) => { assert.strictEqual(name, 'userData'); return USER_DATA; },
    whenReady: () => Promise.resolve(),
    on: () => {},
    quit: () => {},
  },
  BrowserWindow: class {
    static getAllWindows() { return []; }
    constructor(opts) { windowsCreated++; this.opts = opts; }
    loadFile() {}
  },
  ipcMain: { handle: (ch, fn) => { handlers[ch] = fn; } },
  dialog: { showOpenDialog: async () => ({ canceled: true }) },
  contextBridge: { exposeInMainWorld: (name, api) => { exposed[name] = api; } },
  ipcRenderer: { invoke: async (ch) => `invoked:${ch}` },
};

const origLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'electron') return mockElectron;
  return origLoad.call(this, request, ...rest);
};

async function main() {
  const results = [];
  const check = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  };

  // --- setup test files ---
  await fsp.rm('/tmp/aegis-test', { recursive: true, force: true });
  await fsp.mkdir(path.join(SCAN_DIR, 'nested'), { recursive: true });
  await fsp.writeFile(path.join(SCAN_DIR, 'harmless.txt'), 'hello, this is a harmless text file\n');
  await fsp.writeFile(path.join(SCAN_DIR, 'demo.bat'), '@echo off\necho hi\n');
  await fsp.writeFile(path.join(SCAN_DIR, 'sample.ps1'), 'Write-Host "hi"\n');
  // EICAR standard test string, exactly 68 bytes, no trailing newline
  const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  await fsp.writeFile(path.join(SCAN_DIR, 'eicar.txt'), EICAR);
  await fsp.writeFile(path.join(SCAN_DIR, 'nested', 'inner.txt'), 'nested clean file\n');
  const eicarHash = crypto.createHash('sha256').update(EICAR).digest('hex');
  check('EICAR fixture hash matches known bad hash', eicarHash === '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', eicarHash);

  // --- load real main.js ---
  require(path.join(PROJECT, 'main.js'));
  await new Promise((r) => setTimeout(r, 300)); // let whenReady().then run
  check('main.js created a BrowserWindow', windowsCreated === 1, `windows=${windowsCreated}`);
  check('all 7 IPC handlers registered', Object.keys(handlers).length === 7, Object.keys(handlers).join(','));

  const invoke = (ch, ...args) => handlers[ch]({}, ...args);

  // --- dashboard (fresh) ---
  const dash0 = await invoke('app:get-dashboard');
  check('dashboard fresh: quarantineCount 0, protection on', dash0.quarantineCount === 0 && dash0.protectionEnabled === true, JSON.stringify(dash0));

  // --- toggle protection ---
  const off = await invoke('app:toggle-protection', false);
  check('toggle protection off returns false', off === false);
  const on = await invoke('app:toggle-protection', true);
  check('toggle protection on returns true', on === true);

  // --- scan ---
  const scan = await invoke('scan:pick-and-run', SCAN_DIR);
  check('scan not canceled', scan.canceled === false);
  check('scan total = 5 files', scan.summary.totalScanned === 5, `got ${scan.summary.totalScanned}`);
  check('scan flagged = 3', scan.summary.flaggedCount === 3, `got ${scan.summary.flaggedCount}`);
  const byName = Object.fromEntries(scan.files.map((f) => [f.name, f]));
  check('harmless.txt clean', byName['harmless.txt'].flagged === false && byName['harmless.txt'].severity === 'clean');
  check('inner.txt (nested) clean', byName['inner.txt'].flagged === false);
  check('demo.bat warning / extension reason', byName['demo.bat'].flagged === true && byName['demo.bat'].severity === 'warning' && byName['demo.bat'].reason.includes('.bat'), byName['demo.bat'].reason);
  check('sample.ps1 warning', byName['sample.ps1'].flagged === true && byName['sample.ps1'].severity === 'warning');
  check('eicar.txt CRITICAL by hash, not extension', byName['eicar.txt'].flagged === true && byName['eicar.txt'].severity === 'critical' && byName['eicar.txt'].reason.includes('EICAR'), byName['eicar.txt'].reason);
  check('flagged files sorted to top', scan.files[0].flagged && scan.files[1].flagged && scan.files[2].flagged);
  check('scan sha256 prefix shown correctly', byName['eicar.txt'].sha256 === eicarHash);

  // dashboard after scan persists lastScan
  const dash1 = await invoke('app:get-dashboard');
  check('dashboard lastScan persisted', dash1.lastScan && dash1.lastScan.totalScanned === 5 && dash1.lastScan.flaggedCount === 3);

  // --- quarantine demo.bat, then restore ---
  const q1 = await invoke('quarantine:add', byName['demo.bat']);
  check('quarantine demo.bat ok', q1.ok === true && !!q1.entry.id);
  check('original demo.bat moved away', !(await fs.existsSync(path.join(SCAN_DIR, 'demo.bat'))));
  const vaultFiles = await fsp.readdir(path.join(USER_DATA, 'quarantine_vault'));
  check('vault holds 1 .quarantined file', vaultFiles.length === 1 && vaultFiles[0].endsWith('.quarantined'), vaultFiles.join(','));
  let list = await invoke('quarantine:list');
  check('quarantine list = 1, reason preserved', list.length === 1 && list[0].originalName === 'demo.bat');
  const dash2 = await invoke('app:get-dashboard');
  check('dashboard quarantineCount = 1 after quarantine', dash2.quarantineCount === 1);

  const r1 = await invoke('quarantine:restore', q1.entry.id);
  check('restore ok', r1.ok === true);
  check('demo.bat back in original folder', await fs.existsSync(path.join(SCAN_DIR, 'demo.bat')));
  list = await invoke('quarantine:list');
  check('quarantine list empty after restore', list.length === 0);

  // --- quarantine again, then delete ---
  const scan2 = await invoke('scan:pick-and-run', SCAN_DIR);
  const bat2 = scan2.files.find((f) => f.name === 'demo.bat');
  const q2 = await invoke('quarantine:add', bat2);
  const d1 = await invoke('quarantine:delete', q2.entry.id);
  check('delete ok', d1.ok === true);
  check('vault empty after delete', (await fsp.readdir(path.join(USER_DATA, 'quarantine_vault'))).length === 0);
  check('demo.bat NOT restored by delete (permanently gone)', !(await fs.existsSync(path.join(SCAN_DIR, 'demo.bat'))));
  list = await invoke('quarantine:list');
  check('quarantine list empty after delete', list.length === 0);

  // --- error paths ---
  let restoreErr = null;
  try { await invoke('quarantine:restore', 'no-such-id'); } catch (e) { restoreErr = e.message; }
  check('restore unknown id throws', restoreErr === 'Quarantine item not found', restoreErr);
  let deleteErr = null;
  try { await invoke('quarantine:delete', 'no-such-id'); } catch (e) { deleteErr = e.message; }
  check('delete unknown id throws', deleteErr === 'Quarantine item not found', deleteErr);

  // --- preload.js API surface ---
  delete require.cache[require.resolve(path.join(PROJECT, 'preload.js'))];
  require(path.join(PROJECT, 'preload.js'));
  const api = exposed.companionAPI;
  check('preload exposes companionAPI', !!api);
  check('preload exposes all 7 methods', api && ['getDashboard','toggleProtection','pickAndScanFolder','quarantineFile','listQuarantine','restoreQuarantined','deleteQuarantined'].every((m) => typeof api[m] === 'function'));

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) { console.log('FAILED:', failed.map((f) => f.name).join('; ')); process.exit(1); }
}
main().catch((e) => { console.error('TEST HARNESS ERROR', e); process.exit(2); });
