require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const nodemailer = require('nodemailer');
const path = require('path');
const MongoStore = require('connect-mongo');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../public')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Session configuration with MongoDB store (important for serverless)
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions',
        ttl: 60 * 60 // 1 hour
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 // 1 hour
    }
}));

// ----- Mongoose Schema -----
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// Nodemailer transporter (create inside each request for serverless)
const createTransporter = () => {
    return nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
};

// Helper: generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// ----- Routes -----

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// 1. Register / Send OTP
app.post('/api/register', async (req, res) => {
    const { name, email } = req.body;

    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }

    try {
        const existingUser = await User.findOne({ email, isVerified: true });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered and verified' });
        }

        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        await User.findOneAndUpdate(
            { email },
            { name, email, otp, otpExpires, isVerified: false },
            { upsert: true, new: true }
        );

        const transporter = createTransporter();
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP for Registration',
            text: `Hello ${name},\n\nYour OTP is: ${otp}\nIt expires in 5 minutes.\n\nThank you!`
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'OTP sent successfully to your email' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. Verify OTP & Login
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ error: 'Email and OTP are required' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ error: 'User already verified. Please login directly.' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        if (user.otpExpires < new Date()) {
            return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        req.session.userId = user._id;
        req.session.email = user.email;
        req.session.name = user.name;

        res.json({ message: 'Login successful', user: { name: user.name, email: user.email } });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 3. Get dashboard data (protected)
app.get('/api/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const currentUser = await User.findById(req.session.userId).select('name email');
        const allUsers = await User.find({ isVerified: true }).select('name email -_id');
        const totalUsers = allUsers.length;

        res.json({
            currentUser: { name: currentUser.name, email: currentUser.email },
            totalRegistered: totalUsers,
            allUsers: allUsers
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 4. Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out' });
    });
});

// Export for Vercel serverless
module.exports = app;
