const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});

const User = mongoose.model('User', userSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err));

// ========== 1. REGISTER ==========
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ error: 'User already exists' });
  
  const user = new User({ name, email, password });
  await user.save();
  
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  
  res.json({
    success: true,
    token,
    user: { id: user._id, name, email }
  });
});

// ========== 2. LOGIN ==========
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.password !== password) return res.status(401).json({ error: 'Invalid credentials' });
  
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  
  res.json({
    success: true,
    token,
    user: { id: user._id, name: user.name, email }
  });
});

// ========== 3. LOGOUT ==========
app.get('/api/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// ========== MIDDLEWARE TO PROTECT ROUTES ==========
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========== 4. GET CURRENT USER (Protected) ==========
app.get('/api/auth/me', protect, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json({ success: true, user });
});

// ========== 5. GET ALL USERS (Protected) ==========
app.get('/api/users', protect, async (req, res) => {
  const users = await User.find().select('-password');
  res.json({ success: true, count: users.length, users });
});

// ========== START SERVER ==========
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`\n📋 Authentication Endpoints:`);
  console.log(`   POST   /api/auth/register`);
  console.log(`   POST   /api/auth/login`);
  console.log(`   GET    /api/auth/logout`);
  console.log(`   GET    /api/auth/me`);
  console.log(`   GET    /api/users`);
});
