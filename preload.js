const { contextBridge, ipcRenderer } = require('electron');

// Expose only what the renderer needs — no direct Node.js access
contextBridge.exposeInMainWorld('electronAPI', {
  getAPIKeys:     ()       => ipcRenderer.invoke('get-api-keys'),
  saveAPIKeys:    (keys)   => ipcRenderer.invoke('save-api-keys', keys),
  queryAPI:       (params) => ipcRenderer.invoke('query-api', params),
  generateReport: (data)   => ipcRenderer.invoke('generate-report', data),
  openExternal:   (url)    => ipcRenderer.invoke('open-external', url),
});
