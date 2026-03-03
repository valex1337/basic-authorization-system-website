// server.js
require('dotenv').config(); // Load environment variables first
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'fallback_secret_key';

app.use(express.json());
app.use(cors());

// --- RATE LIMITING (Anti-Bruteforce) ---
// Limits a user to 5 login attempts every 15 minutes
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Initialize SQLite Database 
const db = new sqlite3.Database('./portfolio.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
});

// --- REGISTRATION ENDPOINT ---
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                // If the username exists, we still return a generic error or a specific one depending on UX needs. 
                // For reg-check prevention, some prefer generic, but usually, signup needs to tell them it's taken.
                return res.status(409).json({ error: 'Username already taken.' });
            }
            res.status(201).json({ message: 'Account registered successfully!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// --- LOGIN ENDPOINT (Protected with Rate Limiter) ---
app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        // PATCH: Generic error to prevent username enumeration
        if (err || !user) {
            return res.status(401).json({ error: 'Incorrect username or password.' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
                res.json({ message: 'Login successful!', token });
            } else {
                // PATCH: Exact same generic error for wrong password
                res.status(401).json({ error: 'Incorrect username or password.' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Internal server error.' });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Secure Auth server running on http://localhost:${PORT}`);
});