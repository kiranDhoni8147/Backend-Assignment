const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cookieParser());

require('dotenv').config();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(error => console.error('Error connecting to MongoDB:', error));
const db = mongoose.connection;

// User schema
const UserSchema = new mongoose.Schema({
    email: String,
    password: String,
    name: String,
    bio: String,
    phone: String,
    photo: String,
    isPublic: { type: Boolean, default: true },
    isAdmin: { type: Boolean, default: false }
});

const User = mongoose.model('User', UserSchema);
const blacklist = new Set();

// Register a new user
app.post('/register', async (req, res) => {
    try {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            email: req.body.email,
            password: hashedPassword,
            name: req.body.name
        });
        await user.save();
        res.status(201).send();
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


// Login
app.post('/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign({ email: user.email, isAdmin: user.isAdmin }, process.env.ACCESS_TOKEN_SECRET);
            
            // Set the JWT token in a cookie
            res.cookie('token', accessToken, { httpOnly: true });
            
            // Respond with success message or user data
            res.status(200).json({ message: 'Login successful', accessToken: accessToken });
        } else {
            res.status(401).json({ message: 'Authentication failed' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Sign out
app.post('/logout', (req, res) => {
    const token = req.cookies.token;
    blacklist.add(token); 
    res.clearCookie('token');
    res.status(200).json({ message: 'Logged out successfully' });
});


// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    if (!token || blacklist.has(token)) {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Set profile visibility
app.put('/profile/visibility', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOneAndUpdate({ email: req.user.email }, { isPublic: req.body.isPublic }, { new: true });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get user profile based on visibility
app.get('/profile/:email', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.isPublic || req.user.isAdmin) {
            return res.json(user);
        } else {
            return res.status(403).json({ message: 'Access denied' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Get all public user profiles
app.get('/public-profiles', authenticateToken, async (req, res) => {
    try {
        const publicUsers = await User.find({ isPublic: true });
        res.json(publicUsers);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


// Get all users (admin only)
app.get('/users', authenticateToken, async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Access denied' });
        }
        const users = await User.find();
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Update user details
app.put('/edit/profile', authenticateToken, async (req, res) => {
    try {
        // Find the user by email
        const user = await User.findOne({ email: req.user.email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (req.body.name) user.name = req.body.name;
        if (req.body.bio) user.bio = req.body.bio;
        if (req.body.phone) user.phone = req.body.phone;
        if (req.body.photo) user.photo = req.body.photo;

        if (req.body.email && req.body.email !== req.user.email) {
            const existingUser = await User.findOne({ email: req.body.email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already in use' });
            }
            user.email = req.body.email;
        }
        await user.save();
        res.status(200).json({ message: 'User details updated successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
