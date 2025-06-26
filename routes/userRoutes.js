const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Send OTP Email
const sendOTPEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Verification',
    text: `Your OTP is ${otp}`,
  };

  await transporter.sendMail(mailOptions);
};

// Register API
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ msg: 'User already exists' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate OTP
  const otpExpiry = new Date();
  otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP expiry time: 10 minutes

  const user = new User({ name, email, password, otp, otpExpiry });
  await sendOTPEmail(email, otp);

  await user.save();
  res.status(200).json({ msg: 'OTP sent to your email' });
});

// Login API
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Forgot Password API
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: 'User not found' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date();
  otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);

  user.otp = otp;
  user.otpExpiry = otpExpiry;
  await sendOTPEmail(email, otp);

  await user.save();
  res.status(200).json({ msg: 'OTP sent to your email' });
});

// Verify OTP and Reset Password
router.post('/verify-otp', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: 'User not found' });

  if (user.otp !== otp || new Date() > user.otpExpiry) {
    return res.status(400).json({ msg: 'Invalid or expired OTP' });
  }

  user.password = newPassword; // Hashing will be handled by the pre-save middleware
  user.otp = null;
  user.otpExpiry = null;
  await user.save();
  res.status(200).json({ msg: 'Password updated successfully' });
});

module.exports = router;
