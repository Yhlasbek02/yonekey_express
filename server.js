const express = require('express');
const dotenv = require("dotenv");
const sequelize = require('./config/database');
const UserRoutes = require('./routes/userRoutes');
const AdminRoutes = require('./routes/adminRoutes');
dotenv.config();
const app = express();
const PORT = 3000;

app.use(express.json());
app.use('/user', UserRoutes);
app.use('/admin', AdminRoutes);

sequelize
  .sync({alter:true})
  .then(() => {
    console.log('Database connected');
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Error connecting to database:', error);
  });

