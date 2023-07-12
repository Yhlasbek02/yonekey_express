const express = require('express');
const {Op, where} = require("sequelize");
const {Admin, User} = require('../models/models');
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const {checkAdminAuth, restrictToAdmin} = require("../middlewares/auth");
const router = express.Router();

const PasswordReset = () => {
    const otp = Math.floor(100000 + Math.random() * 900000);
    const OTP = otp.toString();
    const expires = Date.now() + 3600000;
    return { OTP, expires };
};

const sendPasswordResetEmail = async (email, OTP) => {
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
      },
    });
  
    const otp = `${OTP}`;
  
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: 'Password Reset',
      html: `<p>Verification code: <em>${otp}</em></p>`,
    };
  
    await transporter.sendMail(mailOptions);
};

router.post('/register', async (req, res) => {
    try {
        const {adminname, email, password, password_conf} = req.body;
        if (!adminname || !email || !password || !password_conf) {
            return res.send({message: "All fields are required"});
        }

        const existingUser = await Admin.findOne({
            where: {
                [Op.or]: [
                    {adminname: adminname},
                    {email:email}
                ]
            }
        });

        if (existingUser) {
            return res.status(409).send({message: "User already registered"})
        }
        if (password !== password_conf) {
            return res.status(409).send({message: "Password and password confirmation don't match"})
        }
        const hashedPassword = await bcryptjs.hash(password, 10);
        const hashedUserId = await bcryptjs.hash(adminname + password, 10);
        const admin = await Admin.create({
            adminname,
            email,
            password: hashedPassword,
            id: hashedUserId
        });
        
        const token = jwt.sign({adminId: admin.adminname}, process.env.SECRET_KEY, { expiresIn: '7 days' });
        res.send({admin, message:"User created successfully", token});
    } catch (error) {
        console.error('Error creating user: ', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        const admin = await Admin.findOne({
            where: { email },
        });
  
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
  
        const isPasswordValid = await bcryptjs.compare(password, user.password);
  
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
  
        const token = jwt.sign({adminId: admin.adminname}, process.env.SECRET_KEY, { expiresIn: '7 days' });
  
        res.json({ message: 'Login successfull', token });
    } catch (error) {
      console.error('Error during login:', error);
      res.status(500).send('An error occurred');
    }
});


router.post('/reset-password', async (req, res) => {
    try {
        const { email } = req.body;
        const admin = await Admin.findOne({ where: { email } });
        
        if (!admin) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { OTP, expires } = PasswordReset();
  
        admin.resetOTP = OTP;
        admin.resetPasswordExpires = new Date(expires);
        await admin.save();
  
    
        await sendPasswordResetEmail(email, OTP);
  
        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error('Error sending password reset email:', error);
        res.status(500).send('An error occurred');
    }
});

router.post('/change-password', async (req, res) => {
    try {
        const {otp, newPassword, newPasswordConfirmation} = req.body;
        const admin = await Admin.findOne({where: {resetOTP: otp}});
        if (!admin) {
            res.status(404).send({message:"User not found"});
        };
        if (newPassword !== newPasswordConfirmation) {
            res.status(409).send({message: "Password and password confirmation don't match"});
        }
        const newHashedPassword = await bcryptjs.hash(newPassword, 10);
        admin.password = newHashedPassword;
        await admin.save();
        res.send({message: "Password changed successfully"});
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('An error occured');
    }
})



router.get('/lists', checkAdminAuth, restrictToAdmin, async (req, res) => {
    try {
        const admins = await Admin.findAll();
        res.json(admins);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('An error occured');
    }
});

router.get('/profile', checkAdminAuth, restrictToAdmin, async (req, res) => {
    try {
        const admin = await Admin.findOne({where: {id: req.admin.id}});
        if (!admin) {
            return res.send({message: "Admin not found"});
        }
        res.send(admin);
    } catch (error) {
        console.error({"Error": error});
        res.send(500).send('An error occured');
    }
})


module.exports = router;
