const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String, required: true,unique: true },
  password: { type: String },
  otp: { type: String }, // OTP for verification
  otpExpiry: { type: Date }, // OTP expiry time
});

module.exports = mongoose.model('User', UserSchema);
