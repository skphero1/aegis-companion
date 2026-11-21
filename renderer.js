let currentScanFolder = null;
let lastScannedFiles = [];
let quarantinedPaths = new Set();

function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
}

function formatDate(isoString) {
  if (!isoString) return 'Never scanned';
  const d = new Date(isoString);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Navigation switching
function switchView(viewName) {
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === viewName);
  });
  document.querySelectorAll('.view').forEach((section) => {
    section.classList.toggle('active', section.id === `view-${viewName}`);
  });

  if (viewName === 'home') refreshDashboard();
  if (viewName === 'quarantine') refreshQuarantine();
}

document.querySelectorAll('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

// ================= HOME VIEW =================
async function refreshDashboard() {
  const data = await window.companionAPI.getDashboard();

  document.getElementById('nav-quarantine-count').textContent = data.quarantineCount;
  document.getElementById('stat-quarantine-total').textContent = `${data.quarantineCount} item${data.quarantineCount === 1 ? '' : 's'}`;
  document.getElementById('vault-path-display').textContent = data.quarantineVaultPath;

  const toggle = document.getElementById('protection-toggle');
  toggle.checked = data.protectionEnabled;
  updateProtectionBanner(data.protectionEnabled);

  if (data.lastScan) {
    document.getElementById('stat-last-scan').textContent = formatDate(data.lastScan.timestamp);
    document.getElementById('stat-last-folder').textContent = data.lastScan.folder;
    document.getElementById('stat-files-checked').textContent = `${data.lastScan.totalScanned} files`;
    document.getElementById('stat-flagged-summary').textContent = `${data.lastScan.flaggedCount} flagged item${data.lastScan.flaggedCount === 1 ? '' : 's'}`;
  }
}

function updateProtectionBanner(enabled) {
  const hero = document.getElementById('protection-hero');
  const headline = document.getElementById('status-headline');
  const subtext = document.getElementById('status-subtext');

  hero.classList.toggle('paused', !enabled);
  headline.textContent = enabled ? 'Companion Guard Active' : 'Companion Guard Paused';
  subtext.textContent = enabled
    ? 'Extension download handoff & local folder inspection ready.'
    : 'Background status toggled off (placeholder state).';
}

document.getElementById('protection-toggle').addEventListener('change', async (e) => {
  const enabled = await window.companionAPI.toggleProtection(e.target.checked);
  updateProtectionBanner(enabled);
  showToast(enabled ? 'Protection enabled' : 'Protection paused');
});

document.getElementById('home-scan-btn').addEventListener('click', () => {
  switchView('scan');
  runFolderScan(null);
});

// ================= SCANNER VIEW =================
async function runFolderScan(existingPath = null) {
  const pickBtn = document.getElementById('btn-pick-folder');
  const rescanBtn = document.getElementById('btn-rescan');
  pickBtn.disabled = true;
  rescanBtn.disabled = true;
  pickBtn.textContent = 'Scanning...';

  try {
    const result = await window.companionAPI.pickAndScanFolder(existingPath);
    if (result.canceled) return;

    currentScanFolder = result.summary.folder;
    lastScannedFiles = result.files;

    document.getElementById('scan-target-path').textContent = currentScanFolder;
    document.getElementById('scan-summary-strip').hidden = false;
    document.getElementById('sum-total').textContent = result.summary.totalScanned;
    document.getElementById('sum-flagged').textContent = result.summary.flaggedCount;
    document.getElementById('sum-clean').textContent =
      result.summary.totalScanned - result.summary.flaggedCount;

    renderScanTable();
    refreshDashboard();
  } finally {
    pickBtn.disabled = false;
    rescanBtn.disabled = !currentScanFolder;
    pickBtn.textContent = 'Pick Folder & Scan';
  }
}

function renderScanTable() {
  const tbody = document.getElementById('scan-results-body');
  const flaggedOnly = document.getElementById('filter-flagged-only').checked;

  const visible = flaggedOnly
    ? lastScannedFiles.filter((f) => f.flagged)
    : lastScannedFiles;

  if (visible.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">${
      lastScannedFiles.length === 0
        ? 'No files found in selected folder.'
        : 'No flagged files match the current filter.'
    }</td></tr>`;
    return;
  }

  tbody.innerHTML = visible
    .map((file, idx) => {
      const isQuarantined = quarantinedPaths.has(file.path);
      const badgeClass =
        file.severity === 'critical'
          ? 'badge-critical'
          : file.severity === 'warning'
          ? 'badge-warning'
          : 'badge-clean';

      return `
        <tr>
          <td>
            <span class="file-name">${escapeHtml(file.name)}</span>
            <span class="file-subpath">${escapeHtml(file.relativePath)}</span>
          </td>
          <td><code>${file.sha256.slice(0, 14)}…</code></td>
          <td><span class="badge ${badgeClass}">${escapeHtml(file.reason)}</span></td>
          <td class="align-right">
            ${
              file.flagged
                ? `<button class="btn-quarantine-sm" data-file-index="${idx}" ${
                    isQuarantined ? 'disabled' : ''
                  }>${isQuarantined ? 'Quarantined ✓' : 'Quarantine'}</button>`
                : `<span class="file-subpath">—</span>`
            }
          </td>
        </tr>
      `;
    })
    .join('');

  tbody.querySelectorAll('.btn-quarantine-sm').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const file = visible[Number(btn.dataset.fileIndex)];
      try {
        await window.companionAPI.quarantineFile(file);
        quarantinedPaths.add(file.path);
        renderScanTable();
        refreshDashboard();
        showToast(`Quarantined: ${file.name}`);
      } catch (err) {
        showToast(`Failed to quarantine: ${err.message}`);
      }
    });
  });
}

document.getElementById('btn-pick-folder').addEventListener('click', () => runFolderScan(null));
document.getElementById('btn-rescan').addEventListener('click', () => runFolderScan(currentScanFolder));
document.getElementById('filter-flagged-only').addEventListener('change', renderScanTable);

// ================= QUARANTINE VIEW =================
async function refreshQuarantine() {
  const items = await window.companionAPI.listQuarantine();
  const tbody = document.getElementById('quarantine-body');
  document.getElementById('nav-quarantine-count').textContent = items.length;

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">No files currently in quarantine.</td></tr>`;
    return;
  }

  tbody.innerHTML = items
    .map(
      (item) => `
      <tr>
        <td>
          <span class="file-name">${escapeHtml(item.originalName)}</span>
          <span class="file-subpath">${escapeHtml(item.originalPath)}</span>
        </td>
        <td><span class="badge badge-warning">${escapeHtml(item.reason)}</span></td>
        <td>${formatDate(item.quarantinedAt)}</td>
        <td class="align-right">
          <button class="btn-teal-sm" data-restore-id="${item.id}">Restore</button>
          <button class="btn-danger-sm" data-delete-id="${item.id}">Delete</button>
        </td>
      </tr>
    `
    )
    .join('');

  tbody.querySelectorAll('[data-restore-id]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await window.companionAPI.restoreQuarantined(btn.dataset.restoreId);
        showToast('File restored to original folder');
        refreshQuarantine();
        refreshDashboard();
      } catch (err) {
        showToast(`Restore failed: ${err.message}`);
      }
    });
  });

  tbody.querySelectorAll('[data-delete-id]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await window.companionAPI.deleteQuarantined(btn.dataset.deleteId);
        showToast('File permanently deleted');
        refreshQuarantine();
        refreshDashboard();
      } catch (err) {
        showToast(`Delete failed: ${err.message}`);
      }
    });
  });
}

document.getElementById('btn-refresh-quarantine').addEventListener('click', refreshQuarantine);

// Initial boot
refreshDashboard();
