const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const jwtSecret = 'your_secret_key';

const users = [];

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const userExists = users.find(u => u.username === username);

    if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
    res.json({ token });
});

const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token missing or invalid' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token is not valid' });
        }
        req.user = user;
        next();
    });
};

app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello, ${req.user.username}!` });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
