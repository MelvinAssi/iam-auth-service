const express = require('express');
require('dotenv').config(); 

const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const sequelize = require('./config/db');

const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: process.env.FRONT_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
}));

app.get('/', (req, res) => {
  res.send('API works correctly!');
});

const authRoutes = require('./routes/auth.route')

app.use('/auth',authRoutes)

const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection to the base successful!');

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server launched on the port ${PORT}`);
    });   
  } catch (error) {
    console.error('Unable to connect to database:', error);
  }
};

startServer();
