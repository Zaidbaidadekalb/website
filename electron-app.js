const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { startServer } = require('./server');

let mainWindow;
let server;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile('index2.html');
}

app.whenReady().then(() => {
    createWindow();

    startServer()
        .then((serverInstance) => {
            server = serverInstance;
            mainWindow.webContents.send('server-status', { status: 'running', port: server.address().port });
        })
        .catch((error) => {
            mainWindow.webContents.send('server-status', { status: 'error', message: error.message });
        });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

ipcMain.on('toggle-server', (event, action) => {
    if (action === 'pause' && server && !server.isPaused) {
        server.close(() => {
            server.isPaused = true;
            event.reply('server-status', { status: 'paused' });
        });
    } else if (action === 'resume' && server && server.isPaused) {
        server = server.listen(server.address() ? server.address().port : 5000, '0.0.0.0', () => {
            server.isPaused = false;
            event.reply('server-status', { status: 'running', port: server.address().port });
        });
    }
});


ipcMain.on('get-errors', (event) => {
    event.reply('server-errors', server.serverErrors);
});



ipcMain.on('clear-errors', (event) => {
    server.serverErrors = [];
    event.reply('server-errors', server.serverErrors);
});


ipcMain.on('get-server-logs', (event) => {
    event.reply('server-logs', server.serverErrors);
});
ipcMain.on('get-server-logs', (event) => {
    event.reply('server-logs', server.serverErrors);
});