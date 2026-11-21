const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('companionAPI', {
  getDashboard: () => ipcRenderer.invoke('app:get-dashboard'),
  toggleProtection: (enabled) => ipcRenderer.invoke('app:toggle-protection', enabled),
  pickAndScanFolder: (existingPath = null) => ipcRenderer.invoke('scan:pick-and-run', existingPath),
  quarantineFile: (fileRecord) => ipcRenderer.invoke('quarantine:add', fileRecord),
  listQuarantine: () => ipcRenderer.invoke('quarantine:list'),
  restoreQuarantined: (id) => ipcRenderer.invoke('quarantine:restore', id),
  deleteQuarantined: (id) => ipcRenderer.invoke('quarantine:delete', id)
});
