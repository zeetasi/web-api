const express = require('express');
const path = require('path');
const db = require('./db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: process.env.VERCEL ? '/tmp' : './'
    }),
    secret: 'ganti-dengan-secret-key-yang-sangat-aman',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

app.get('/', (req, res) => {
    res.redirect(req.session.userId ? '/dashboard' : '/login');
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render('register', { error: 'Username and password are required.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
        db.run(sql, [username, hashedPassword], function(err) {
            if (err) return res.render('register', { error: 'Username already taken.' });
            res.redirect('/login');
        });
    } catch {
        res.render('register', { error: 'An error occurred during registration.' });
    }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], async (err, user) => {
        if (err || !user || !await bcrypt.compare(password, user.password_hash)) {
            return res.render('login', { error: 'Invalid username or password.' });
        }
        req.session.userId = user.id;
        res.redirect('/dashboard');
    });
});

app.get('/dashboard', requireLogin, (req, res) => {
    const sql = 'SELECT id, username, api_key FROM users WHERE id = ?';
    db.get(sql, [req.session.userId], (err, user) => {
        if (err || !user) return res.redirect('/login');
        res.render('dashboard', { user: user });
    });
});

app.post('/generate-key', requireLogin, (req, res) => {
    const newApiKey = uuidv4();
    const sql = 'UPDATE users SET api_key = ? WHERE id = ?';
    db.run(sql, [newApiKey, req.session.userId], () => res.redirect('/dashboard'));
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

const authenticateApiKey = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ status: 'error', message: 'API Key required' });

    const sql = 'SELECT id, username FROM users WHERE api_key = ?';
    db.get(sql, [token], (err, user) => {
        if (err || !user) return res.status(403).json({ status: 'error', message: 'Invalid API Key' });
        req.user = user;
        next();
    });
};

app.get('/api/v1/check', authenticateApiKey, (req, res) => {
    res.json({ status: 'success', message: 'API Key is valid', user: { username: req.user.username } });
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));

module.exports = app;