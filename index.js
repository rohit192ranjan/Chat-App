const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const JWT_SECRET = process.env.JWT_SECRET; // Use a strong secret in production

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from the 'public' directory

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { dbName: process.env.DB_NAME, useNewUrlParser: true, useUnifiedTopology: true });

// Define schemas and models
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String
});

const messageSchema = new mongoose.Schema({
    from: String,
    to: String,
    text: String,
    timestamp: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send('User registered');
    } catch (error) {
        res.status(400).send('Error registering user');
    }
});

// Authenticate user and get token
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Middleware to verify JWT
const authenticate = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send('Access denied');
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).send('Invalid token');
    }
};

// Get unread messages count for each user
app.get('/unread-messages', authenticate, async (req, res) => {
    const unreadMessages = await Message.aggregate([
        { $match: { to: req.user.username, read: false } },
        { $group: { _id: '$from', count: { $sum: 1 } } }
    ]);
    res.json(unreadMessages);
});

// Mark messages as read
app.post('/messages/mark-read/:withUser', authenticate, async (req, res) => {
    const { withUser } = req.params;
    await Message.updateMany(
        { from: withUser, to: req.user.username, read: false },
        { $set: { read: true } }
    );
    res.status(200).send('Messages marked as read');
});

// Get user list (except the current user)
app.get('/users', authenticate, async (req, res) => {
    const users = await User.find({ username: { $ne: req.user.username } }, 'username');
    res.json(users);
});

// Get messages between the authenticated user and another user
app.get('/messages/:withUser', authenticate, async (req, res) => {
    const { withUser } = req.params;
    const messages = await Message.find({
        $or: [
            { from: req.user.username, to: withUser },
            { from: withUser, to: req.user.username }
        ]
    }).sort({ timestamp: 1 });
    res.json(messages);
});

// Handle real-time messaging
io.on('connection', (socket) => {
    console.log('socket connected');

    socket.on('join', (username) => {
        socket.username = username;
        console.log(`User joined: ${username}`);
        socket.broadcast.emit('user connected', username);
    });

    socket.on('private message', async ({ to, text }) => {
        if (socket.username && to && text) {
            const message = new Message({ from: socket.username, to, text });
            await message.save();
            io.to(to).emit('private message', { from: socket.username, text });
            io.to(socket.username).emit('private message', { from: socket.username, text });
        } else {
            console.error('Message received from unidentified user or missing fields');
        }
    });

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

const PORT = process.env.PORT;
server.listen(PORT, () => {
    console.log(`Server listening on port:${PORT}`);
});
