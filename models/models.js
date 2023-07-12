const {DataTypes} = require("sequelize");
const sequelize = require("../config/database");

const User = sequelize.define('User', {
    id: {
        type: DataTypes.STRING,
        allowNull: false,
        primaryKey: true
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
        type:DataTypes.STRING,
        allowNull:false,
        validate: {
            isEmail: true,
        }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'user',
    },
    resetOTP: {
        type: DataTypes.STRING,
        defaultValue: null
    },
    resetPasswordExpires: {
        type: DataTypes.DATE,
        defaultValue: null
    }
});

const Admin = sequelize.define('Admin', {
    id: {
        type: DataTypes.STRING,
        allowNull: false,
        primaryKey: true
    },
    adminname: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull:false,
        validate: {
            isEmail: true,
        }
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'admin',
    },
    resetOTP: {
        type: DataTypes.STRING,
        defaultValue: null
    },
    resetPasswordExpires: {
        type: DataTypes.DATE,
        defaultValue: null
    }
})

module.exports = {User, Admin};