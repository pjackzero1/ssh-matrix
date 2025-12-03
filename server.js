const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const net = require('net');
const http = require('http');
const https = require('https');
const expressWs = require('express-ws');
const { Client } = require('ssh2');
const crypto = require('crypto');

const app = express();
expressWs(app);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

app.use(express.json());
app.use(express.static('public'));
app.use(express.static(__dirname + '/public'));

// Database Setup
const dbDir = process.env.DB_DIR || './data';
console.log('DB_DIR:', dbDir);

// Ensure directory exists
try {
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log('Created directory:', dbDir);
  }
} catch (err) {
  console.error('Error creating directory:', err);
}

const dbPath = path.join(dbDir, 'ssh-matrix.db');
console.log('DB Path:', dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('DB Connection Error:', err);
    process.exit(1);
  } else {
    console.log('SQLite connected:', dbPath);
    setTimeout(() => {
      console.log('Initializing database...');
      initDatabase();
    }, 200);
  }
});

// Promisify db.run for async/await
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

// Promisify db.get for async/await
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Promisify db.all for async/await
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(rows || []);
      else resolve(rows || []);
    });
  });
}

// Audit Log Function
async function logAudit(userId, username, action, targetType, targetId, targetName, details, ipAddress) {
  try {
    await dbRun(
      'INSERT INTO audit_logs (user_id, username, action, target_type, target_id, target_name, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, username, action, targetType, targetId, targetName, details, ipAddress]
    );
  } catch (err) {
    console.error('Audit log error:', err);
  }
}

// ===== 2FA TOTP Functions =====
function generateTOTPSecret() {
  const buffer = crypto.randomBytes(20);
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  for (let i = 0; i < buffer.length; i++) {
    secret += base32chars[buffer[i] % 32];
  }
  return secret;
}

function base32Decode(base32) {
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < base32.length; i++) {
    const val = base32chars.indexOf(base32[i].toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTOTP(secret, timeStep = 30, digits = 6) {
  const time = Math.floor(Date.now() / 1000 / timeStep);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigInt64BE(BigInt(time));
  
  const key = base32Decode(secret);
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0xf;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

function verifyTOTP(secret, token, window = 1) {
  for (let i = -window; i <= window; i++) {
    const time = Math.floor(Date.now() / 1000 / 30) + i;
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));
    
    const key = base32Decode(secret);
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(timeBuffer);
    const hash = hmac.digest();
    
    const offset = hash[hash.length - 1] & 0xf;
    const binary = ((hash[offset] & 0x7f) << 24) |
                   ((hash[offset + 1] & 0xff) << 16) |
                   ((hash[offset + 2] & 0xff) << 8) |
                   (hash[offset + 3] & 0xff);
    
    const otp = (binary % Math.pow(10, 6)).toString().padStart(6, '0');
    if (otp === token) return true;
  }
  return false;
}

function initDatabase() {
  db.serialize(() => {
    // User Groups Table
    db.run(`CREATE TABLE IF NOT EXISTS user_groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      permissions TEXT DEFAULT 'read',
      color TEXT DEFAULT '#00ff00',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Users Table with 2FA and Dashboard permission
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'inactive',
      totp_secret TEXT,
      totp_enabled INTEGER DEFAULT 0,
      can_view_dashboard INTEGER DEFAULT 0,
      group_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(group_id) REFERENCES user_groups(id)
    )`);

    // Migration: Add columns if not exist
    db.run(`ALTER TABLE users ADD COLUMN totp_secret TEXT`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });
    db.run(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });
    db.run(`ALTER TABLE users ADD COLUMN can_view_dashboard INTEGER DEFAULT 0`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });
    db.run(`ALTER TABLE users ADD COLUMN group_id INTEGER`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });

    // SSH Servers Table
    db.run(`CREATE TABLE IF NOT EXISTS ssh_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER DEFAULT 22,
      description TEXT,
      external_url TEXT,
      status TEXT DEFAULT 'offline',
      last_check DATETIME,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    db.run(`ALTER TABLE ssh_servers ADD COLUMN external_url TEXT`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });

    // HTML Servers Table
    db.run(`CREATE TABLE IF NOT EXISTS html_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER DEFAULT 80,
      protocol TEXT DEFAULT 'http',
      description TEXT,
      external_url TEXT,
      status TEXT DEFAULT 'offline',
      last_check DATETIME,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    db.run(`ALTER TABLE html_servers ADD COLUMN external_url TEXT`, (err) => {
      if (err && !err.message.includes('duplicate column')) console.error(err);
    });

    // Fritzboxes Table
    db.run(`CREATE TABLE IF NOT EXISTS fritzboxes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      ip TEXT NOT NULL,
      external_url TEXT,
      status TEXT DEFAULT 'offline',
      last_check DATETIME,
      last_output TEXT,
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )`);

    // Audit Log Table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id INTEGER,
      target_name TEXT,
      details TEXT,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Default Groups
    db.get('SELECT * FROM user_groups WHERE name = ?', ['Administratoren'], (err, row) => {
      if (!row) {
        db.run('INSERT INTO user_groups (name, description, permissions, color) VALUES (?, ?, ?, ?)',
          ['Administratoren', 'Volle Rechte', 'read,write', '#ff0000'],
          (err) => { if (!err) console.log('Group Administratoren created'); }
        );
      }
    });

    db.get('SELECT * FROM user_groups WHERE name = ?', ['Benutzer'], (err, row) => {
      if (!row) {
        db.run('INSERT INTO user_groups (name, description, permissions, color) VALUES (?, ?, ?, ?)',
          ['Benutzer', 'Standard Benutzer - Nur Lesen', 'read', '#00ff00'],
          (err) => { if (!err) console.log('Group Benutzer created'); }
        );
      }
    });

    db.get('SELECT * FROM user_groups WHERE name = ?', ['Power User'], (err, row) => {
      if (!row) {
        db.run('INSERT INTO user_groups (name, description, permissions, color) VALUES (?, ?, ?, ?)',
          ['Power User', 'Lesen und Schreiben', 'read,write', '#ffff00'],
          (err) => { if (!err) console.log('Group Power User created'); }
        );
      }
    });

    // Default Admin User
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
      if (!row) {
        const hashedPW = bcrypt.hashSync('admin123', 10);
        db.run('INSERT INTO users (username, password, role, status, can_view_dashboard) VALUES (?, ?, ?, ?, ?)',
          ['admin', hashedPW, 'admin', 'active', 1],
          (err) => {
            if (!err) console.log('Admin user created: admin / admin123');
          }
        );
      } else {
        db.run('UPDATE users SET can_view_dashboard = 1 WHERE username = ?', ['admin']);
      }
    });
  });
}


// ===== CHECK FUNCTIONS =====

// TCP Port Check (for SSH and other TCP services)
function checkTCP(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    
    socket.setTimeout(timeout);
    
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', () => {
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

// HTTP/HTTPS Check
function checkHTTP(url, timeout = 5000) {
  return new Promise((resolve) => {
    const protocol = url.startsWith('https') ? https : http;
    
    const req = protocol.get(url, { timeout }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 500);
      res.resume();
    });
    
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

// ===== MIDDLEWARE =====
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalid or expired' });
    }
    req.user = decoded;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin permission required' });
  }
  next();
}

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const hashedPW = bcrypt.hashSync(password, 10);
    await dbRun('INSERT INTO users (username, password, role, status, can_view_dashboard) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPW, 'user', 'inactive', 0]);
    
    res.status(201).json({ message: 'Registration successful! Admin must approve.' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'User already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, totpToken } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    
    if (!user) {
      await logAudit(null, username, 'LOGIN_FAILED', 'user', null, username, 'User not found', ipAddress);
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.status === 'inactive') {
      await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, username, 'Account inactive', ipAddress);
      return res.status(401).json({ error: 'Account not yet approved. Please contact admin.' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
      await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, username, 'Wrong password', ipAddress);
      return res.status(401).json({ error: 'Password incorrect' });
    }

    // Check 2FA if enabled
    if (user.totp_enabled === 1) {
      if (!totpToken) {
        return res.status(200).json({ requires2FA: true, message: '2FA code required' });
      }
      if (!verifyTOTP(user.totp_secret, totpToken)) {
        await logAudit(user.id, username, 'LOGIN_FAILED', 'user', user.id, username, 'Invalid 2FA code', ipAddress);
        return res.status(401).json({ error: '2FA code invalid' });
      }
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, canViewDashboard: user.can_view_dashboard === 1 },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    await logAudit(user.id, username, 'LOGIN_SUCCESS', 'user', user.id, username, 'Login successful', ipAddress);
    
    res.json({
      token,
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        canViewDashboard: user.can_view_dashboard === 1,
        totpEnabled: user.totp_enabled === 1
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== 2FA ROUTES =====
app.post('/api/2fa/setup', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (user.totp_enabled === 1) {
      return res.status(400).json({ error: '2FA already enabled' });
    }

    const secret = generateTOTPSecret();
    await dbRun('UPDATE users SET totp_secret = ? WHERE id = ?', [secret, userId]);

    const otpauthUrl = `otpauth://totp/SSH-Matrix:${user.username}?secret=${secret}&issuer=SSH-Matrix&algorithm=SHA1&digits=6&period=30`;
    
    res.json({ 
      secret,
      otpauthUrl,
      message: 'Scan the QR code with your authenticator app'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/2fa/verify', verifyToken, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    
    const user = await dbGet('SELECT totp_secret FROM users WHERE id = ?', [userId]);
    
    if (!user.totp_secret) {
      return res.status(400).json({ error: '2FA not set up yet' });
    }

    if (verifyTOTP(user.totp_secret, token)) {
      await dbRun('UPDATE users SET totp_enabled = 1 WHERE id = ?', [userId]);
      res.json({ success: true, message: '2FA successfully enabled' });
    } else {
      res.status(400).json({ error: 'Invalid code' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/2fa/disable', verifyToken, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user.id;
    
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Password incorrect' });
    }

    await dbRun('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [userId]);
    res.json({ success: true, message: '2FA disabled' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/2fa/status', verifyToken, async (req, res) => {
  try {
    const user = await dbGet('SELECT totp_enabled FROM users WHERE id = ?', [req.user.id]);
    res.json({ enabled: user.totp_enabled === 1 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== SSH SERVERS =====
app.get('/api/ssh-servers', verifyToken, async (req, res) => {
  try {
    const servers = await dbAll('SELECT * FROM ssh_servers ORDER BY created_at DESC');
    res.json(servers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ssh-servers', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, host, port, description, external_url } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (!name || !host) {
      return res.status(400).json({ error: 'Name and host required' });
    }
    
    const result = await dbRun(
      'INSERT INTO ssh_servers (name, host, port, description, external_url, created_by, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, host, port || 22, description || '', external_url || '', req.user.id, 'offline']
    );
    
    await logAudit(req.user.id, req.user.username, 'CREATE', 'ssh_server', result.id, name, `Created SSH server: ${host}:${port}`, ipAddress);
    
    res.status(201).json({ id: result.id, message: 'SSH server added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/ssh-servers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, host, port, description, external_url } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (!name || !host) {
      return res.status(400).json({ error: 'Name and host required' });
    }
    
    await dbRun(
      'UPDATE ssh_servers SET name=?, host=?, port=?, description=?, external_url=? WHERE id=?',
      [name, host, port || 22, description || '', external_url || '', req.params.id]
    );
    
    await logAudit(req.user.id, req.user.username, 'UPDATE', 'ssh_server', parseInt(req.params.id), name, `Updated SSH server: ${host}:${port}`, ipAddress);
    
    res.json({ message: 'SSH server updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/ssh-servers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    const server = await dbGet('SELECT name FROM ssh_servers WHERE id=?', [req.params.id]);
    
    await dbRun('DELETE FROM ssh_servers WHERE id=?', [req.params.id]);
    
    await logAudit(req.user.id, req.user.username, 'DELETE', 'ssh_server', parseInt(req.params.id), server?.name || 'Unknown', 'Deleted SSH server', ipAddress);
    
    res.json({ message: 'SSH server deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== HTML SERVERS =====
app.get('/api/html-servers', verifyToken, async (req, res) => {
  try {
    const servers = await dbAll('SELECT * FROM html_servers ORDER BY created_at DESC');
    res.json(servers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/html-servers', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, host, port, protocol, description, external_url } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (!name || !host) {
      return res.status(400).json({ error: 'Name and host required' });
    }
    
    const result = await dbRun(
      'INSERT INTO html_servers (name, host, port, protocol, description, external_url, created_by, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, host, port || 80, protocol || 'http', description || '', external_url || '', req.user.id, 'offline']
    );
    
    await logAudit(req.user.id, req.user.username, 'CREATE', 'html_server', result.id, name, `Created HTML server: ${protocol}://${host}:${port}`, ipAddress);
    
    res.status(201).json({ id: result.id, message: 'HTML server added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/html-servers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, host, port, protocol, description, external_url } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (!name || !host) {
      return res.status(400).json({ error: 'Name and host required' });
    }
    
    await dbRun(
      'UPDATE html_servers SET name=?, host=?, port=?, protocol=?, description=?, external_url=? WHERE id=?',
      [name, host, port || 80, protocol || 'http', description || '', external_url || '', req.params.id]
    );
    
    await logAudit(req.user.id, req.user.username, 'UPDATE', 'html_server', parseInt(req.params.id), name, `Updated HTML server: ${protocol}://${host}:${port}`, ipAddress);
    
    res.json({ message: 'HTML server updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/html-servers/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    const server = await dbGet('SELECT name FROM html_servers WHERE id=?', [req.params.id]);
    
    await dbRun('DELETE FROM html_servers WHERE id=?', [req.params.id]);
    
    await logAudit(req.user.id, req.user.username, 'DELETE', 'html_server', parseInt(req.params.id), server?.name || 'Unknown', 'Deleted HTML server', ipAddress);
    
    res.json({ message: 'HTML server deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== FRITZBOXES =====
app.get('/api/fritzboxes', verifyToken, async (req, res) => {
  try {
    const fritzboxes = await dbAll('SELECT * FROM fritzboxes ORDER BY created_at DESC');
    res.json(fritzboxes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/fritzboxes', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, ip, external_url } = req.body;
    
    if (!name || !ip) {
      return res.status(400).json({ error: 'Name and IP required' });
    }
    
    const result = await dbRun(
      'INSERT INTO fritzboxes (name, ip, external_url, created_by, status) VALUES (?, ?, ?, ?, ?)',
      [name, ip, external_url || '', req.user.id, 'offline']
    );
    
    res.status(201).json({ id: result.id, message: 'Fritzbox added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/fritzboxes/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, ip, external_url } = req.body;
    
    if (!name || !ip) {
      return res.status(400).json({ error: 'Name and IP required' });
    }
    
    await dbRun(
      'UPDATE fritzboxes SET name=?, ip=?, external_url=? WHERE id=?',
      [name, ip, external_url || '', req.params.id]
    );
    
    res.json({ message: 'Fritzbox updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/fritzboxes/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    await dbRun('DELETE FROM fritzboxes WHERE id=?', [req.params.id]);
    res.json({ message: 'Fritzbox deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== USERS MANAGEMENT =====
app.get('/api/users', verifyToken, isAdmin, async (req, res) => {
  try {
    console.log('GET /api/users called by user:', req.user.username);
    
    const users = await dbAll(`
      SELECT u.id, u.username, u.role, u.status, u.can_view_dashboard, u.totp_enabled, u.group_id, u.created_at,
             g.name as group_name, g.permissions as group_permissions, g.color as group_color
      FROM users u
      LEFT JOIN user_groups g ON u.group_id = g.id
      ORDER BY u.created_at DESC
    `);
    
    console.log('Users query result:', users);
    console.log('Number of users:', users.length);
    
    res.json(users);
  } catch (err) {
    console.error('Error loading users:', err.message);
    console.error('Error stack:', err.stack);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { role, status, canViewDashboard } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    const targetUser = await dbGet('SELECT username FROM users WHERE id=?', [req.params.id]);
    
    if (role && !['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    if (status && !['active', 'inactive'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    let updates = [];
    let values = [];
    let changes = [];

    if (role) {
      updates.push('role=?');
      values.push(role);
      changes.push(`role: ${role}`);
    }

    if (status) {
      updates.push('status=?');
      values.push(status);
      changes.push(`status: ${status}`);
    }

    if (canViewDashboard !== undefined) {
      updates.push('can_view_dashboard=?');
      values.push(canViewDashboard ? 1 : 0);
      changes.push(`dashboard: ${canViewDashboard}`);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    values.push(parseInt(req.params.id));
    await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id=?`, values);
    
    await logAudit(req.user.id, req.user.username, 'UPDATE_USER', 'user', parseInt(req.params.id), targetUser?.username || 'Unknown', changes.join(', '), ipAddress);
    
    res.json({ message: 'User updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete own account' });
    }
    
    const targetUser = await dbGet('SELECT username FROM users WHERE id=?', [userId]);
    
    await dbRun('DELETE FROM users WHERE id=?', [userId]);
    
    await logAudit(req.user.id, req.user.username, 'DELETE_USER', 'user', userId, targetUser?.username || 'Unknown', 'Deleted user', ipAddress);
    
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/reset-password', verifyToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    const defaultPassword = 'password123';
    const hashedPW = bcrypt.hashSync(defaultPassword, 10);
    
    const targetUser = await dbGet('SELECT username FROM users WHERE id=?', [userId]);
    
    await dbRun('UPDATE users SET password=? WHERE id=?', [hashedPW, userId]);
    
    await logAudit(req.user.id, req.user.username, 'RESET_PASSWORD', 'user', userId, targetUser?.username || 'Unknown', 'Password reset to default', ipAddress);
    
    res.json({ message: 'Password reset' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/reset-2fa', verifyToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    const targetUser = await dbGet('SELECT username FROM users WHERE id=?', [userId]);
    
    await dbRun('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [userId]);
    
    await logAudit(req.user.id, req.user.username, 'RESET_2FA', 'user', userId, targetUser?.username || 'Unknown', '2FA reset', ipAddress);
    
    res.json({ message: '2FA reset' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/change-password', verifyToken, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = parseInt(req.params.id);
    
    if (userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const hashedPW = bcrypt.hashSync(password, 10);
    await dbRun('UPDATE users SET password=? WHERE id=?', [hashedPW, userId]);
    res.json({ message: 'Password changed' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== USER GROUPS =====
app.get('/api/groups', verifyToken, async (req, res) => {
  try {
    const groups = await dbAll('SELECT * FROM user_groups ORDER BY name ASC');
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/groups', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, description, permissions, color } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name required' });
    }
    
    const result = await dbRun(
      'INSERT INTO user_groups (name, description, permissions, color) VALUES (?, ?, ?, ?)',
      [name, description || '', permissions || 'read', color || '#00ff00']
    );
    
    res.status(201).json({ id: result.id, message: 'Group created' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Group name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/groups/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, description, permissions, color } = req.body;
    const groupId = parseInt(req.params.id);
    
    if (!name) {
      return res.status(400).json({ error: 'Name required' });
    }
    
    await dbRun(
      'UPDATE user_groups SET name=?, description=?, permissions=?, color=? WHERE id=?',
      [name, description || '', permissions || 'read', color || '#00ff00', groupId]
    );
    
    res.json({ message: 'Group updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/groups/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const groupId = parseInt(req.params.id);
    
    await dbRun('UPDATE users SET group_id = NULL WHERE group_id = ?', [groupId]);
    await dbRun('DELETE FROM user_groups WHERE id=?', [groupId]);
    res.json({ message: 'Group deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/group', verifyToken, isAdmin, async (req, res) => {
  try {
    const { groupId } = req.body;
    const userId = parseInt(req.params.id);
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    
    const targetUser = await dbGet('SELECT username FROM users WHERE id=?', [userId]);
    const group = groupId ? await dbGet('SELECT name FROM user_groups WHERE id=?', [groupId]) : null;
    
    await dbRun('UPDATE users SET group_id = ? WHERE id = ?', [groupId || null, userId]);
    
    await logAudit(req.user.id, req.user.username, 'UPDATE_GROUP', 'user', userId, targetUser?.username || 'Unknown', `Group changed to: ${group?.name || 'None'}`, ipAddress);
    
    res.json({ message: 'User group updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== AUDIT LOGS =====
app.get('/api/audit-logs', verifyToken, isAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    const userId = req.query.userId;
    
    let query = 'SELECT * FROM audit_logs';
    let params = [];
    
    if (userId) {
      query += ' WHERE user_id = ?';
      params.push(userId);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const logs = await dbAll(query, params);
    const countResult = await dbGet('SELECT COUNT(*) as total FROM audit_logs' + (userId ? ' WHERE user_id = ?' : ''), userId ? [userId] : []);
    
    res.json({
      logs,
      total: countResult?.total || 0,
      limit,
      offset
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/audit-logs', verifyToken, isAdmin, async (req, res) => {
  try {
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
    const { olderThan } = req.body;
    
    let query = 'DELETE FROM audit_logs';
    let params = [];
    
    if (olderThan) {
      query += ' WHERE created_at < datetime("now", "-" || ? || " days")';
      params.push(olderThan);
    }
    
    const result = await dbRun(query, params);
    
    await logAudit(req.user.id, req.user.username, 'CLEAR_AUDIT_LOGS', 'system', null, null, `Cleared ${result.changes} audit logs` + (olderThan ? ` older than ${olderThan} days` : ''), ipAddress);
    
    res.json({ message: `${result.changes} audit logs deleted` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== STATUS CHECK =====
app.post('/api/check-status/:type/:id', verifyToken, async (req, res) => {
  try {
    const type = req.params.type;
    const id = parseInt(req.params.id);
    
    if (type === 'ssh') {
      const server = await dbGet('SELECT * FROM ssh_servers WHERE id=?', [id]);
      if (!server) return res.status(404).json({ error: 'SSH server not found' });
      
      console.log(`Checking SSH Server: ${server.host}:${server.port}`);
      const isAlive = await checkTCP(server.host, server.port);
      const status = isAlive ? 'online' : 'offline';
      
      await dbRun('UPDATE ssh_servers SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, id]);
      console.log(`SSH Server ${server.name}: ${status}`);
      res.json({ status });
      
    } else if (type === 'html') {
      const server = await dbGet('SELECT * FROM html_servers WHERE id=?', [id]);
      if (!server) return res.status(404).json({ error: 'HTML server not found' });
      
      const url = `${server.protocol}://${server.host}:${server.port}`;
      console.log(`Checking HTML Server: ${url}`);
      
      let status = await checkHTTP(url) ? 'online' : 'offline';
      
      if (status === 'offline') {
        const isAlive = await checkTCP(server.host, server.port);
        status = isAlive ? 'online' : 'offline';
      }
      
      await dbRun('UPDATE html_servers SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, id]);
      console.log(`HTML Server ${server.name}: ${status}`);
      res.json({ status });
      
    } else if (type === 'fritzbox') {
      const fb = await dbGet('SELECT * FROM fritzboxes WHERE id=?', [id]);
      if (!fb) return res.status(404).json({ error: 'Fritzbox not found' });
      
      console.log(`Checking Fritzbox: ${fb.ip}`);
      
      const url = `http://${fb.ip}:80`;
      let status = await checkHTTP(url) ? 'online' : 'offline';
      
      if (status === 'offline') {
        const isAlive = await checkTCP(fb.ip, 443);
        status = isAlive ? 'online' : 'offline';
      }
      
      if (status === 'offline') {
        const isAlive = await checkTCP(fb.ip, 80);
        status = isAlive ? 'online' : 'offline';
      }
      
      await dbRun('UPDATE fritzboxes SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, fb.id]);
      console.log(`Fritzbox ${fb.name}: ${status}`);
      res.json({ status });
      
    } else {
      res.status(400).json({ error: 'Unknown type' });
    }
  } catch (err) {
    console.error('Error in check-status:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== AUTO-CHECK ALL SERVERS =====
async function autoCheckAll() {
  console.log('\n[Auto-Check] Starting...');
  try {
    // SSH Servers
    const sshServers = await dbAll('SELECT id, name, host, port FROM ssh_servers');
    console.log(`Found ${sshServers.length} SSH Servers`);
    for (const server of sshServers) {
      try {
        const isAlive = await checkTCP(server.host, server.port);
        const status = isAlive ? 'online' : 'offline';
        await dbRun('UPDATE ssh_servers SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, server.id]);
        console.log(`[OK] SSH Server ${server.id} (${server.host}:${server.port}): ${status}`);
      } catch (e) {
        console.error(`Error checking SSH Server ${server.id}:`, e.message);
      }
    }
    
    // HTML Servers
    const htmlServers = await dbAll('SELECT id, name, protocol, host, port FROM html_servers');
    console.log(`Found ${htmlServers.length} HTML Servers`);
    for (const server of htmlServers) {
      try {
        const url = `${server.protocol}://${server.host}:${server.port}`;
        let status = await checkHTTP(url) ? 'online' : 'offline';
        if (status === 'offline') {
          const isAlive = await checkTCP(server.host, server.port);
          status = isAlive ? 'online' : 'offline';
        }
        await dbRun('UPDATE html_servers SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, server.id]);
        console.log(`[OK] HTML Server ${server.id} (${server.host}:${server.port}): ${status}`);
      } catch (e) {
        console.error(`Error checking HTML Server ${server.id}:`, e.message);
      }
    }
    
    // Fritzboxes
    const fritzboxes = await dbAll('SELECT id, name, ip FROM fritzboxes');
    console.log(`Found ${fritzboxes.length} Fritzboxes`);
    for (const fb of fritzboxes) {
      try {
        const url = `http://${fb.ip}:80`;
        let status = await checkHTTP(url) ? 'online' : 'offline';
        if (status === 'offline') {
          const isAlive = await checkTCP(fb.ip, 443);
          status = isAlive ? 'online' : 'offline';
        }
        if (status === 'offline') {
          const isAlive = await checkTCP(fb.ip, 80);
          status = isAlive ? 'online' : 'offline';
        }
        await dbRun('UPDATE fritzboxes SET status=?, last_check=CURRENT_TIMESTAMP WHERE id=?', [status, fb.id]);
        console.log(`[OK] Fritzbox ${fb.id} (${fb.ip}): ${status}`);
      } catch (e) {
        console.error(`Error checking Fritzbox ${fb.id}:`, e.message);
      }
    }
    
    console.log('[Auto-Check] Complete\n');
  } catch (err) {
    console.error('Error in auto-check:', err.message);
  }
}

// ===== FRONTEND ROUTE =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== SSH WEBSOCKET =====
app.ws('/ssh/:id', (ws, req) => {
  console.log('========================================');
  console.log('[SSH] WebSocket connection attempt');
  console.log('Server ID:', req.params.id);
  
  let sshClient = null;
  let stream = null;

  ws.on('message', async (msg) => {
    try {
      const data = JSON.parse(msg);
      console.log('[SSH] Received message type:', data.type);
      
      if (data.type === 'auth') {
        const serverId = parseInt(req.params.id);
        const server = await dbGet('SELECT * FROM ssh_servers WHERE id=?', [serverId]);
        
        if (!server) {
          console.error('[SSH] Server not found:', serverId);
          ws.send(JSON.stringify({ type: 'error', data: 'Server not found' }));
          return;
        }

        console.log('[SSH] Server Details:');
        console.log('   Name:', server.name);
        console.log('   Host:', server.host);
        console.log('   Port:', server.port);
        console.log('   Username:', data.username);
        console.log('========================================');
        console.log(`[SSH] Connecting to: ${server.host}:${server.port} as ${data.username}`);

        sshClient = new Client();
        
        sshClient.on('ready', () => {
          console.log('[SSH] Client ready - Handshake successful!');
          ws.send(JSON.stringify({ type: 'status', data: 'connected' }));
          
          sshClient.shell({ term: 'xterm-256color' }, (err, channel) => {
            if (err) {
              console.error('[SSH] Shell error:', err.message);
              ws.send(JSON.stringify({ type: 'error', data: err.message }));
              return;
            }
            
            console.log('[SSH] Shell opened successfully');
            stream = channel;
            
            channel.on('data', (data) => {
              const output = data.toString('utf-8');
              console.log('[SSH] Output:', output.length, 'bytes');
              ws.send(JSON.stringify({ type: 'output', data: output }));
            });
            
            channel.on('close', () => {
              console.log('[SSH] Channel closed');
              ws.send(JSON.stringify({ type: 'status', data: 'disconnected' }));
              ws.close();
            });

            channel.stderr.on('data', (data) => {
              const output = data.toString('utf-8');
              console.log('[SSH] Stderr:', output);
              ws.send(JSON.stringify({ type: 'output', data: output }));
            });
          });
        });

        sshClient.on('error', (err) => {
          console.error('[SSH] Error:', err.message);
          console.error('   Code:', err.code);
          console.error('   Level:', err.level);
          
          let errorMsg = err.message;
          
          if (err.level === 'client-socket') {
            errorMsg = `Connection failed: ${server.host}:${server.port} not reachable`;
          } else if (err.level === 'client-authentication') {
            errorMsg = 'Authentication failed: Wrong username or password';
          } else if (err.code === 'ECONNREFUSED') {
            errorMsg = `Port ${server.port} is closed or SSH server not running`;
          } else if (err.code === 'ETIMEDOUT') {
            errorMsg = `Timeout: Host ${server.host} not responding`;
          } else if (err.message.includes('handshake')) {
            errorMsg = `SSH handshake failed on ${server.host}:${server.port}`;
          }
          
          ws.send(JSON.stringify({ type: 'error', data: errorMsg }));
          ws.close();
        });

        sshClient.on('close', () => {
          console.log('[SSH] Connection closed');
        });

        sshClient.on('end', () => {
          console.log('[SSH] Connection ended');
        });

        try {
          console.log('[SSH] Starting connection...');
          sshClient.connect({
            host: server.host,
            port: server.port,
            username: data.username,
            password: data.password,
            readyTimeout: 10000,
            tryKeyboard: true,
            debug: (msg) => {
              console.log('[SSH2 Debug]:', msg);
            }
          });
        } catch (err) {
          console.error('[SSH] Connect error:', err.message);
          ws.send(JSON.stringify({ type: 'error', data: err.message }));
        }
      } else if (data.type === 'input' && stream) {
        console.log('[SSH] Sending input:', data.data.charCodeAt(0));
        stream.write(data.data);
      } else if (data.type === 'resize' && stream) {
        console.log('[SSH] Resizing terminal:', data.rows, 'x', data.cols);
        stream.setWindow(data.rows, data.cols);
      }
    } catch (e) {
      console.error('[SSH] WebSocket message error:', e);
      ws.send(JSON.stringify({ type: 'error', data: e.message }));
    }
  });

  ws.on('close', () => {
    console.log('[SSH] WebSocket closed');
    if (stream) {
      stream.end();
      stream = null;
    }
    if (sshClient) {
      sshClient.end();
      sshClient = null;
    }
  });

  ws.on('error', (err) => {
    console.error('[SSH] WebSocket error:', err.message);
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ===== SERVER START =====
app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║        SSH MATRIX Server running           ║');
  console.log(`║    http://localhost:${PORT}`.padEnd(45) + '║');
  console.log('╠════════════════════════════════════════════╣');
  console.log('║  Login Credentials:                        ║');
  console.log('║  Username: admin                           ║');
  console.log('║  Password: admin123                        ║');
  console.log('╚════════════════════════════════════════════╝\n');
  
  console.log('[Timer] Starting initial auto-check in 5 seconds...');
  setTimeout(() => {
    autoCheckAll();
    setInterval(autoCheckAll, 5 * 60 * 1000);
  }, 5000);
});

process.on('SIGINT', () => {
  console.log('\nServer shutting down...');
  db.close();
  process.exit(0);
});
