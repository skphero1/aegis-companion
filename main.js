const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

// App storage paths inside OS userData (e.g., %APPDATA%\aegis-companion on Windows)
const USER_DATA_DIR = app.getPath('userData');
const QUARANTINE_DIR = path.join(USER_DATA_DIR, 'quarantine_vault');
const MANIFEST_PATH = path.join(USER_DATA_DIR, 'quarantine-manifest.json');
const STATE_PATH = path.join(USER_DATA_DIR, 'app-state.json');

// ============================================================================
// [PLACEHOLDER SCAN LOGIC] — Example Heuristic Extensions & Mock Bad Hashes
// Replace this block with real YARA rules, ClamAV/AMSI bindings, or cloud API.
// ============================================================================
const PLACEHOLDER_SUSPICIOUS_EXTENSIONS = new Set([
  '.exe',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.scr',
  '.js',
  '.dll'
]);

const PLACEHOLDER_BAD_HASHES = new Map([
  // Standard EICAR antivirus test file SHA-256 hash
  [
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    'EICAR-Test-Signature (Demo)'
  ],
  // Example mock malware hash (empty file SHA-256 included only for easy testing if desired — disabled by default)
  [
    'deadbeef00000000000000000000000000000000000000000000000000000001',
    'Trojan.Generic.MockSample'
  ]
]);

function evaluateFilePlaceholder(filePath, sha256) {
  const ext = path.extname(filePath).toLowerCase();

  if (PLACEHOLDER_BAD_HASHES.has(sha256)) {
    return {
      flagged: true,
      severity: 'critical',
      reason: `Known Bad Hash: ${PLACEHOLDER_BAD_HASHES.get(sha256)}`
    };
  }

  if (PLACEHOLDER_SUSPICIOUS_EXTENSIONS.has(ext)) {
    return {
      flagged: true,
      severity: 'warning',
      reason: `Suspicious Executable/Script Extension (${ext})`
    };
  }

  return {
    flagged: false,
    severity: 'clean',
    reason: 'No threats detected'
  };
}
// ============================================================================

async function ensureStorage() {
  await fs.mkdir(QUARANTINE_DIR, { recursive: true });
}

async function readJson(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

async function writeJson(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

async function computeSha256(filePath) {
  const buffer = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

async function collectFiles(rootDir, maxFiles = 300) {
  const results = [];
  const ignoredDirs = new Set(['node_modules', '.git', '$RECYCLE.BIN', 'System Volume Information']);

  async function walk(currentDir) {
    if (results.length >= maxFiles) return;
    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return; // Skip protected/unreadable directories
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) break;
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!ignoredDirs.has(entry.name)) {
          await walk(fullPath);
        }
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return results;
}

// Safe file move across Windows drive letters (handles EXDEV cross-device rename)
async function moveFileSafe(src, dest) {
  try {
    await fs.rename(src, dest);
  } catch (err) {
    if (err.code === 'EXDEV') {
      await fs.copyFile(src, dest);
      await fs.unlink(src);
    } else {
      throw err;
    }
  }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1020,
    height: 680,
    minWidth: 880,
    minHeight: 580,
    backgroundColor: '#0b0e17',
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0b0e17',
      symbolColor: '#94a3b8',
      height: 38
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile('index.html');
}

app.whenReady().then(async () => {
  await ensureStorage();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ================= IPC HANDLERS =================

ipcMain.handle('app:get-dashboard', async () => {
  const state = await readJson(STATE_PATH, {
    lastScan: null,
    protectionEnabled: true
  });
  const quarantine = await readJson(MANIFEST_PATH, []);
  return {
    ...state,
    quarantineCount: quarantine.length,
    quarantineVaultPath: QUARANTINE_DIR
  };
});

ipcMain.handle('app:toggle-protection', async (_event, enabled) => {
  const state = await readJson(STATE_PATH, { lastScan: null, protectionEnabled: true });
  state.protectionEnabled = Boolean(enabled);
  await writeJson(STATE_PATH, state);
  return state.protectionEnabled;
});

ipcMain.handle('scan:pick-and-run', async (_event, existingFolderPath = null) => {
  let targetFolder = existingFolderPath;

  if (!targetFolder) {
    const pick = await dialog.showOpenDialog({
      title: 'Select Folder to Scan',
      properties: ['openDirectory']
    });
    if (pick.canceled || pick.filePaths.length === 0) {
      return { canceled: true };
    }
    targetFolder = pick.filePaths[0];
  }

  const filePaths = await collectFiles(targetFolder, 300);
  const scannedFiles = [];

  for (const filePath of filePaths) {
    try {
      const stat = await fs.stat(filePath);
      const sha256 = await computeSha256(filePath);
      const verdict = evaluateFilePlaceholder(filePath, sha256);

      scannedFiles.push({
        name: path.basename(filePath),
        path: filePath,
        relativePath: path.relative(targetFolder, filePath) || path.basename(filePath),
        size: stat.size,
        sha256,
        flagged: verdict.flagged,
        severity: verdict.severity,
        reason: verdict.reason
      });
    } catch {
      // Skip locked files
    }
  }

  // Sort flagged files to the top
  scannedFiles.sort((a, b) => Number(b.flagged) - Number(a.flagged));

  const flaggedCount = scannedFiles.filter((f) => f.flagged).length;
  const summary = {
    timestamp: new Date().toISOString(),
    folder: targetFolder,
    totalScanned: scannedFiles.length,
    flaggedCount
  };

  const state = await readJson(STATE_PATH, { protectionEnabled: true });
  state.lastScan = summary;
  await writeJson(STATE_PATH, state);

  return {
    canceled: false,
    summary,
    files: scannedFiles
  };
});

ipcMain.handle('quarantine:add', async (_event, fileRecord) => {
  await ensureStorage();
  const manifest = await readJson(MANIFEST_PATH, []);

  const id = crypto.randomUUID();
  const vaultFileName = `${id}.quarantined`;
  const vaultFilePath = path.join(QUARANTINE_DIR, vaultFileName);

  await moveFileSafe(fileRecord.path, vaultFilePath);

  const entry = {
    id,
    originalName: fileRecord.name,
    originalPath: fileRecord.path,
    vaultFileName,
    reason: fileRecord.reason,
    sha256: fileRecord.sha256,
    quarantinedAt: new Date().toISOString()
  };

  manifest.unshift(entry);
  await writeJson(MANIFEST_PATH, manifest);
  return { ok: true, entry };
});

ipcMain.handle('quarantine:list', async () => {
  return await readJson(MANIFEST_PATH, []);
});

ipcMain.handle('quarantine:restore', async (_event, id) => {
  const manifest = await readJson(MANIFEST_PATH, []);
  const idx = manifest.findIndex((item) => item.id === id);
  if (idx === -1) throw new Error('Quarantine item not found');

  const item = manifest[idx];
  const vaultFilePath = path.join(QUARANTINE_DIR, item.vaultFileName);

  await fs.mkdir(path.dirname(item.originalPath), { recursive: true });
  await moveFileSafe(vaultFilePath, item.originalPath);

  manifest.splice(idx, 1);
  await writeJson(MANIFEST_PATH, manifest);
  return { ok: true };
});

ipcMain.handle('quarantine:delete', async (_event, id) => {
  const manifest = await readJson(MANIFEST_PATH, []);
  const idx = manifest.findIndex((item) => item.id === id);
  if (idx === -1) throw new Error('Quarantine item not found');

  const item = manifest[idx];
  const vaultFilePath = path.join(QUARANTINE_DIR, item.vaultFileName);

  try {
    await fs.unlink(vaultFilePath);
  } catch {
    // Ignore if already removed externally
  }

  manifest.splice(idx, 1);
  await writeJson(MANIFEST_PATH, manifest);
  return { ok: true };
});
