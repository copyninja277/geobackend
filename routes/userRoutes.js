const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const router = express.Router();
let otpStore = {};

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

// Register API (Step 1)
router.post('/register', async (req, res) => {
  const { email } = req.body;

  // Check if user already exists in the database (optional)
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ msg: 'User already exists' });

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date();
  otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP expiry time: 10 minutes

  // Store OTP in memory (key: email, value: {otp, otpExpiry})
  otpStore[email] = { otp, otpExpiry };

  // Send OTP email to user
  await sendOTPEmail(email, otp);

  res.status(200).json({ msg: 'OTP sent to your email, please verify to continue' });
});

router.post('/reg-verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  // Check if OTP exists in memory
  const storedOtpData = otpStore[email];
  if (!storedOtpData) {
    return res.status(400).json({ msg: 'OTP not found for this email' });
  }

  // Check if the OTP is expired
  if (new Date() > storedOtpData.otpExpiry) {
    delete otpStore[email]; // Remove expired OTP from memory
    return res.status(400).json({ msg: 'OTP has expired' });
  }

  // Compare the OTPs
  if (storedOtpData.otp !== otp) {
    return res.status(400).json({ msg: 'Invalid OTP' });
  }

  // OTP is valid, proceed to registration step
  delete otpStore[email]; // Remove OTP from memory after successful verification

  res.status(200).json({
    msg: 'OTP verified successfully. Please enter your username and password to complete registration.',
  });
});

// Register with Username and Password (Step 3)
router.post('/complete-registration', async (req, res) => {
  const { email, name, password } = req.body;

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  user.email: email;
  user.name: name;
  user.password: hashedPassword;

  await user.save();
  res.status(200).json({ msg: 'Registration complete! You can now log in.' });
});


// Login API
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the email exists in the database
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ msg: 'User not found' });
  }
  console.log(req.body);
  // Compare entered password with the stored hash
  const isMatch = await bcrypt.compare(password, user.password);
  console.log('Password comparison result:', isMatch); 
  if (!isMatch) {
    return res.status(400).json({ msg: 'Invalid credentials' });
  }

  // If credentials are valid, generate a JWT token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '100h' });
  res.json({ token });  // Send the token back to the client
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
