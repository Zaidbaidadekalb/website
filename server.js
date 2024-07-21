require("dotenv").config();
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;
const serverStartTime = new Date();
let isPaused = false;
let pauseStartTime = null;
let totalPausedTime = 0;
let serverLogs = [];

function addLog(message, type = 'info') {
    const log = `[${new Date().toISOString()}] [${type.toUpperCase()}] ${message}`;
    serverLogs.push(log);
    console.log(log);
}

app.use((err, req, res, next) => {
    addLog(err.stack, 'error');
    res.status(500).json({ error: "An unexpected error occurred" });
});

const checkServerPaused = (req, res, next) => {
    if (
        isPaused &&
        !req.path.startsWith("/status") &&
        !req.path.startsWith("/resume")
    ) {
        return res
            .status(503)
            .json({ error: "Server is paused. Operations are not available." });
    }
    next();
};

app.use(checkServerPaused);

async function initDatabase() {
    db = await open({
        filename: path.join(__dirname, "database.sqlite"),
        driver: sqlite3.Database,
        mode: sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE
    });

    await db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE,
      expirationDate TEXT,
      isWhitelisted INTEGER,
      maxUsage TEXT,
      usageCount INTEGER DEFAULT 0,
      lastUsed TEXT,
      hwid TEXT
    )
  `);

    await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT
    )
  `);

    await db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      action TEXT,
      timestamp TEXT,
      FOREIGN KEY (userId) REFERENCES users(id)
    )
  `);

    const columnCheck = await db.all("PRAGMA table_info(users);");
    const columns = columnCheck.map((col) => col.name);
    if (!columns.includes("role")) {
        await db.exec("ALTER TABLE users ADD COLUMN role TEXT;");
    }

    const hashedPassword = await bcrypt.hash("Jake_kajj2", 10);
    await db.run(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ["admin", hashedPassword, "admin"]
    );
}

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get("/status", (req, res) => {
    const uptime = process.uptime();
    const adjustedUptime = isPaused ?
        pauseStartTime - totalPausedTime :
        uptime - totalPausedTime;
    const hours = Math.floor(adjustedUptime / 3600);
    const minutes = Math.floor((adjustedUptime % 3600) / 60);
    const seconds = Math.floor(adjustedUptime % 60);

    const runtimeFormatted = `${hours}h ${minutes}m ${seconds}s`;

    res.json({
        status: isPaused ? "Server is paused" : "Server is up and running",
        runtime: runtimeFormatted,
        isPaused: isPaused,
    });
});

app.post("/pause", (req, res) => {
    if (!isPaused) {
        isPaused = true;
        pauseStartTime = process.uptime();
        addLog("Server paused", 'info');
        res.json({ message: "Server paused successfully" });
    } else {
        res.status(400).json({ error: "Server is already paused" });
    }
});

app.post("/resume", (req, res) => {
    if (isPaused) {
        isPaused = false;
        totalPausedTime += process.uptime() - pauseStartTime;
        pauseStartTime = null;
        addLog("Server resumed", 'info');
        res.json({ message: "Server resumed successfully" });
    } else {
        res.status(400).json({ error: "Server is not paused" });
    }
});

const JWT_SECRET_KEY = "3576358973126508735";

const checkRole = (requiredRole) => {
    return (req, res, next) => {
        if (req.user && req.user.role === requiredRole) {
            next();
        } else {
            res
                .status(403)
                .json({ error: "Access denied. Insufficient permissions." });
        }
    };
};

function generateKey() {
    const randomPart = Math.random()
        .toString(36)
        .substring(2, 1000)
        .toUpperCase();
    return `KEY-${randomPart}`;
}

async function logAction(userId, action) {
    await db.run(
        "INSERT INTO audit_logs (userId, action, timestamp) VALUES (?, ?, ?)", [userId, action, new Date().toISOString()]
    );
}

app.post("/keys", async(req, res) => {
    try {
        const { key, expirationDate, isWhitelisted, maxUsage, hwid } = req.body;
        const generatedKey = key || generateKey();
        const result = await db.run(
            "INSERT INTO keys (key, expirationDate, isWhitelisted, maxUsage, hwid) VALUES (?, ?, ?, ?, ?)", [
                generatedKey,
                expirationDate,
                isWhitelisted ? 1 : 0,
                maxUsage || "1",
                hwid,
            ]
        );
        addLog(`Key created: ${generatedKey}`, 'info');
        res.json({
            id: result.lastID,
            key: generatedKey,
            expirationDate,
            isWhitelisted,
            maxUsage,
            hwid,
        });
    } catch (error) {
        addLog(`Error creating key: ${error.message}`, 'error');
        res.status(500).json({ error: "Error creating key" });
    }
});

app.get("/keys", async(req, res) => {
    try {
        const keys = await db.all("SELECT * FROM keys");
        res.json(
            keys.map((key) => ({...key, isWhitelisted: !!key.isWhitelisted }))
        );
    } catch (error) {
        addLog(`Error fetching keys: ${error.message}`, 'error');
        res.status(500).json({ error: "Error fetching keys" });
    }
});

app.put("/keys/:id", async(req, res) => {
    try {
        const { expirationDate, isWhitelisted, maxUsage } = req.body;
        await db.run(
            "UPDATE keys SET expirationDate = ?, isWhitelisted = ?, maxUsage = ? WHERE id = ?", [expirationDate, isWhitelisted ? 1 : 0, maxUsage, req.params.id]
        );
        const updatedKey = await db.get(
            "SELECT * FROM keys WHERE id = ?",
            req.params.id
        );
        if (updatedKey) {
            addLog(`Key updated: ${updatedKey.key}`, 'info');
            res.json({...updatedKey, isWhitelisted: !!updatedKey.isWhitelisted });
        } else {
            res.status(404).json({ error: "Key not found" });
        }
    } catch (error) {
        addLog(`Error updating key: ${error.message}`, 'error');
        res.status(500).json({ error: "Error updating key" });
    }
});

app.post("/validate", async(req, res) => {
    try {
        const { key, hwid } = req.body;
        const keyData = await db.get("SELECT * FROM keys WHERE key = ?", key);

        if (keyData) {
            if (!keyData.hwid) {
                await db.run("UPDATE keys SET hwid = ? WHERE key = ?", [hwid, key]);
                addLog(`Associated key ${key} with HWID ${hwid}`, 'info');
            } else if (keyData.hwid !== hwid) {
                addLog(`HWID mismatch for key ${key}. Expected ${keyData.hwid}, got ${hwid}`, 'warning');
                return res.json({ valid: false, error: "HWID mismatch. This key is associated with a different device." });
            }

            if (keyData.isWhitelisted && new Date() < new Date(keyData.expirationDate)) {
                await db.run(
                    "UPDATE keys SET usageCount = usageCount + 1, lastUsed = ? WHERE key = ?", [new Date().toISOString(), key]
                );

                if (keyData.usageCount + 1 >= keyData.maxUsage) {
                    await db.run("UPDATE keys SET isWhitelisted = 0 WHERE key = ?", key);
                    addLog(`Key ${key} reached max usage and was deactivated`, 'info');
                }

                addLog(`Key ${key} validated successfully`, 'info');
                res.json({ valid: true });
            } else {
                addLog(`Invalid validation attempt for key ${key}`, 'warning');
                res.json({ valid: false, error: "Key is not valid or has expired" });
            }
        } else {
            addLog(`Invalid key validation attempt: ${key}`, 'warning');
            res.json({ valid: false, error: "Invalid key" });
        }
    } catch (error) {
        addLog(`Error validating key: ${error.message}`, 'error');
        res.status(500).json({ error: "Error validating key" });
    }
});

app.post("/login", async(req, res) => {
    try {
        const { username, password } = req.body;
        const user = await db.get("SELECT * FROM users WHERE username = ?", username);

        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET_KEY, {
                expiresIn: "1h",
            });

            addLog(`User logged in: ${username}`, 'info');
            res.json({ token });
        } else {
            addLog(`Failed login attempt for user: ${username}`, 'warning');
            res.status(401).json({ error: "Invalid username or password" });
        }
    } catch (error) {
        addLog(`Error logging in: ${error.message}`, 'error');
        res.status(500).json({ error: "Error logging in" });
    }
});

app.post("/users", async(req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.run(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role]
        );
        await logAction(result.lastID, "create_user");
        addLog(`New user created: ${username}`, 'info');
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        addLog(`Error creating user: ${error.message}`, 'error');
        res.status(500).json({ error: "Error creating user" });
    }
});

app.post("/reset-password", async(req, res) => {
    try {
        const { username, newPassword } = req.body;
        const user = await db.get(
            "SELECT * FROM users WHERE username = ?",
            username
        );
        if (user) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await db.run("UPDATE users SET password = ? WHERE username = ?", [
                hashedPassword,
                username,
            ]);
            await logAction(user.id, "reset_password");
            addLog(`Password reset for user: ${username}`, 'info');
            res.json({ success: true });
        } else {
            addLog(`Password reset attempt for non-existent user: ${username}`, 'warning');
            res.status(404).json({ error: "User not found" });
        }
    } catch (error) {
        addLog(`Error resetting password: ${error.message}`, 'error');
        res.status(500).json({ error: "Error resetting password" });
    }
});

app.post("/register", async(req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role]
        );
        addLog(`New user registered: ${username}`, 'info');
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        addLog(`Error registering user: ${error.message}`, 'error');
        res.status(500).json({ error: "Error registering user" });
    }
});

app.delete("/keys", async(req, res) => {
    try {
        await db.run("DELETE FROM keys");
        addLog("All keys deleted", 'info');
        res.json({ success: true, message: "All keys have been deleted" });
    } catch (error) {
        addLog(`Error deleting all keys: ${error.message}`, 'error');
        res.status(500).json({ error: "Error deleting all keys" });
    }
});

app.delete("/keys/:id", checkRole("admin"), async(req, res) => {
    try {
        const result = await db.run("DELETE FROM keys WHERE id = ?", req.params.id);
        if (result.stmt.changes > 0) {
            addLog(`Key deleted: ${req.params.id}`, 'info');
            res.json({ message: "Key deleted successfully" });
        } else {
            res.status(404).json({ error: "Key not found" });
        }
    } catch (error) {
        addLog(`Error deleting key: ${error.message}`, 'error');
        res.status(500).json({ error: "Error deleting key" });
    }
});

app.get("/logs", (req, res) => {
    res.json(serverLogs);
});

app.post("/clear-logs", (req, res) => {
    serverLogs = [];
    addLog("Server logs cleared", 'info');
    res.json({ message: "Server logs cleared" });
});

const PORT = process.env.PORT || 5000;


function startServer() {
    return new Promise((resolve, reject) => {
        initDatabase()
            .then(() => {
                const server = app.listen(PORT, '0.0.0.0', () => {
                    addLog(`Server is running on port ${PORT}`, 'info');
                    server.isPaused = false;
                    server.serverLogs = serverLogs; // Expose serverLogs
                    resolve(server);
                });
            })
            .catch((error) => {
                addLog(`Failed to initialize database: ${error.message}`, 'error');
                reject(error);
            });
    });
}
module.exports = { startServer };