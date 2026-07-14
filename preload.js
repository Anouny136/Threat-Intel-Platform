const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getAPIKeys:     ()       => ipcRenderer.invoke('get-api-keys'),
  saveAPIKeys:    (keys)   => ipcRenderer.invoke('save-api-keys', keys),
  clearAPIKeys:   ()       => ipcRenderer.invoke('save-api-keys', {}),
  queryAPI:       (params) => ipcRenderer.invoke('query-api', params),
  generateReport: (data)   => ipcRenderer.invoke('generate-report', data),
  openExternal:   (url)    => ipcRenderer.invoke('open-external', url),
  checkSetup:           ()       => ipcRenderer.invoke('check-setup'),
  zoomIn:               ()       => ipcRenderer.invoke('zoom-in'),
  zoomOut:              ()       => ipcRenderer.invoke('zoom-out'),
  zoomReset:            ()       => ipcRenderer.invoke('zoom-reset'),
  getZoom:              ()       => ipcRenderer.invoke('get-zoom'),
  generateCombinedReport:  (d)    => ipcRenderer.invoke('generate-combined-report', d),
  attackGetCache:          ()     => ipcRenderer.invoke('attack-get-cache'),
  attackCheckVersion:      ()     => ipcRenderer.invoke('attack-check-version'),
  attackDownload:          ()     => ipcRenderer.invoke('attack-download'),
  onAttackProgress:        (cb)   => ipcRenderer.on('attack-progress', (_, data) => cb(data)),
  offAttackProgress:       ()     => ipcRenderer.removeAllListeners('attack-progress'),
  runInstall:     (params) => ipcRenderer.invoke('run-install', params),
});
