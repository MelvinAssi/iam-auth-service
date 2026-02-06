const express = require('express');
require('dotenv').config(); 
const sequelize = require('./config/db');

const app = express();

app.get('/', (req, res) => {
  res.send('API works correctly!');
});

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
