const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const fetch = require('node-fetch'); // <-- add this

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Database connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Routes
const userRoutes = require('./routes/userRoutes');
app.use('/api/users', userRoutes);

// ✅ Add a simple ping route
app.get('/', (req, res) => {
  res.send('Server is running fine 🟢');
});

// ✅ Self-ping every 14 minutes to prevent Render from sleeping
const SELF_URL = process.env.RENDER_EXTERNAL_URL || 'https://geobackend-c8kh.onrender.com';

setInterval(() => {
  fetch(SELF_URL)
    .then(() => console.log('🔄 Pinged self to stay awake'))
    .catch(err => console.log('Ping failed:', err.message));
}, 14 * 60 * 1000); // every 14 minutes

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
