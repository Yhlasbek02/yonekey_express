const Sequelize = require('sequelize');

const sequelize = new Sequelize('express_db', 'root', '', {
  host: 'localhost',
  dialect: 'mysql',
});

module.exports = sequelize;
