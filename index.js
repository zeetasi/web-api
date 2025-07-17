const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: 'ganti-dengan-secret-key-yang-sangat-aman-dan-panjang',
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

app.get('/register', (req, res) => {
    res.render('register', { title: 'Register - Premium API', error: null });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render('register', { title: 'Register - Premium API', error: 'Username and password are required.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const { error } = await supabase
            .from('users')
            .insert({ username: username, password_hash: hashedPassword });
        
        if (error) throw error;
        
        res.redirect('/login');
    } catch (error) {
        res.render('register', { title: 'Register - Premium API', error: 'Username already taken or server error.' });
    }
});

app.get('/login', (req, res) => {
    res.render('login', { title: 'Login - Premium API', error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !user) throw new Error('Invalid credentials');

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) throw new Error('Invalid credentials');

        req.session.userId = user.id;
        res.redirect('/dashboard');
    } catch (error) {
        res.render('login', { title: 'Login - Premium API', error: 'Invalid username or password.' });
    }
});

app.get('/dashboard', requireLogin, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, username, api_key')
            .eq('id', req.session.userId)
            .single();
        
        if (error || !user) throw new Error('User not found');
        
        res.render('dashboard', { title: 'Dashboard', user: user });
    } catch (error) {
        res.redirect('/login');
    }
});

app.post('/generate-key', requireLogin, async (req, res) => {
    const newApiKey = uuidv4();
    await supabase
        .from('users')
        .update({ api_key: newApiKey })
        .eq('id', req.session.userId);
    res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

const authenticateApiKey = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ status: 'error', message: 'API Key required' });

    const { data: user, error } = await supabase
        .from('users')
        .select('id, username')
        .eq('api_key', token)
        .single();
    
    if (error || !user) {
        return res.status(403).json({ status: 'error', message: 'Invalid API Key' });
    }
    req.user = user;
    next();
};

app.get('/api/v1/check', authenticateApiKey, (req, res) => {
    res.json({ status: 'success', message: 'API Key is valid', user: { username: req.user.username } });
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));

module.exports = app;