const jwt = require('jsonwebtoken')
const User = require('../models/userSchema');
const cookieParser = require('cookie-parser');

// to get token
// to send cookie for front end to backend we have installed cookie parser
const Authenticate = async (req, res, next) => {
    try {


        const token = req.cookies.userToken;
        const verifyToken = jwt.verify(token, process.env.SECRET_KEY);
        const rootUser = await User.findOne({ _id: verifyToken._id, "tokens.token": token })

//        console.log(token);

        if (!rootUser) {
            throw new Error('user not found');
        }

        req.token = token;
        req.rootUser = rootUser;
        req.userID = rootUser._id;

        next();

    } catch (err) {
        res.status(401).send('unauthorized : no token provided');
        console.log(`error is - ${err}`)
    }

}


module.exports = Authenticate;