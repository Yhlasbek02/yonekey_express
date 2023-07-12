const jwt = require("jsonwebtoken");
const {User, Admin} = require("../models/models");


const checkAdminAuth = async (req, res, next) => {
    let token
    const {authorization} = req.headers;
    if (authorization && authorization.startsWith('Bearer')) {
        try {
            token = authorization.split(' ')[1]
            console.log(token)
            const {adminId} = jwt.verify(token, process.env.SECRET_KEY);
            req.admin = await Admin.findOne({
                where: { adminname: adminId },
                attributes: { exclude: ['password'] },
            });
            next();
        } catch (error) {
            console.log(error);
            res.status(401).send({"message":"Unathorized User"});
        }
    }
    if (!token) {
        res.status(401).send({"message":"Unathorized User, No token"});
    }
}



const checkUserAuth = async (req, res, next) => {
    let token
    const {authorization} = req.headers;
    if (authorization && authorization.startsWith('Bearer')) {
        try {
            token = authorization.split(' ')[1]
            console.log(token)
            const {userId} = jwt.verify(token, process.env.SECRET_KEY);
            console.log(userId)
            const user = await User.findOne({
                where: { username: userId },
                attributes: { exclude: ['password'] },
            });
            if (!user) {
                res.send({message: "User not found"});
            }
            req.user = user
            next();
        } catch (error) {
            console.log(error);
            res.status(401).send({"message":"Unathorized User"});
        }
    }
    if (!token) {
        res.status(401).send({"message":"Unathorized User, No token"});
    }
}


const restrictToAdmin = (req, res, next) => {
    if (!req.admin || req.admin.role !== "admin") {
        console.log(req.admin)
        return res.status(403).json({ error: "Access denied" });
    }
    next();
};

module.exports= {checkUserAuth, restrictToAdmin, checkAdminAuth};