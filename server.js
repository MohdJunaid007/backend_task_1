

const jwt = require('jsonwebtoken')
const dotenv = require("dotenv");
const mongoose = require('mongoose');
const express = require('express');
const bcrypt = require('bcryptjs');
const app = express();
const authenticate = require('./middleware/Authenticate')
const cookieParser = require('cookie-parser');
const { Auth, LoginCredentials } = require("two-step-auth");
const Auth = require("two-step-auth");
const nodemailer = require("nodemailer");
const sendEmail = require('./utils/sendEmail')
const passwordReset = require("./routes/passwordReset");


dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE;
const PORT = process.env.PORT || 5000;

mongoose.connect(DB, {
    useNewUrlParser: true,

    useUnifiedTopology: true


}).then(() => {
    console.log(`Connection successful`);
}).catch((err) => console.log(`no connection - ${err}`));


const User = require('./models/userSchema');

app.use(express.json());
app.use(cookieParser())


//// code for register page ////
//``````````````````````````//
app.post('/register', async (req, res) => {

    const { name, lName, email, password, status, cPassword, username } = req.body;


    const usernameExist = await User.findOne({ username: username })
    const emailExist = await User.findOne({ email: email });
    if (emailExist) {
        console.log('i am here userexist');
        return res.status(401).json({ error: "email already exist" });
    }

    if (usernameExist) {
        console.log('i am here userexist');
        return res.status(401).json({ error: "username already exist" });
    }


    if (password != cPassword) {
        console.log('i am at password chhecker');
        return res.status(406).json({ error: "password and confirm password must be same." });
    }

    if ((!name) || (!email) || (!password) || (!cPassword) || (!lName)) {
        console.log('here 422');
        return res.status(422).json({ error: "please fill all the fields properly" })
    }

    const emailvalidator = require("email-validator");
    if (!(emailvalidator.validate(email))) {
        return res.status(400).json({ error: 'Invalid Email' });
    }

    var passwordValidator = require('password-validator');
    var schema = new passwordValidator();

    schema
        .is().min(8)                                    // Minimum length 8
        .is().max(16)                                  // Maximum length 16
        .has().uppercase()                              // Must have uppercase letters
        .has().lowercase()                              // Must have lowercase letters
        .has().digits(2)                                // Must have at least 2 digits
        .has().not().spaces()

    if (!schema.validate(password)) {
        return res.status(415).json({ error: 'Password must be strong' });
    }
    try {

        async function loginSend(emailId) {
            try {
                const res = await Auth(emailId, "OverPay");
                console.log(res);
                console.log(res.mail);
                console.log(res.OTP);
                console.log(res.success);
            } catch (error) {
                console.log(error);
            }
        }
        LoginCredentials.mailID = "yourmailId@anydomain.com";


        LoginCredentials.password = "Your password";
        LoginCredentials.use = true;

        loginSend(email);

        const user = new User({ username, name, email, password, status, cPassword: cPassword });

        const userRegister = await user.save();
        console.log(userRegister);


        if (userRegister) {
            return res.status(201).json({ message: "user registered successfully" });
        }
    }
    catch (err) {
        console.log(`find error - ${err}`);
    }
});





/// code for LOGIN page ///
///`````````````````````````///

app.post('/login', async (req, res) => {


    try {

        const { username, email, password } = req.body;

        let conditions = !!username ? { username: username } : { email: email };

        if ((!password) || (!conditions)) {

            return res.status(400).json({ error: "no fields should be empty" });
        }

        const userLogin = await User.findOne({ conditions });

        if ((userLogin == null)) {
            return res.status(400).json({ error: "invalid details {user not found}" });
        }

        const isMatch = await bcrypt.compare(password, userLogin.password);
        ///////creating token jwt for user authentication
        const token = await userLogin.generateAuthToken();


        // cookie
        await res.cookie("userToken", token, {
            expires: new Date(Date.now() + 25892000000),   // after 30 days token will expire
            httpOnly: true
        });

        if (isMatch) {
            await User.updateOne({ conditions }, { $set: { ModifiedDate: new Date(Date.now()).toString() } })
            return res.status(201).json({ ok: "successfully login" });
        }
        else {
            return res.status(400).json({ error: "invalid details {password is wrong}" });

        }

    } catch (err) {
        console.log(`error = ${err}`);
    }

});


/// this is profile page it will only open after you will sussessfully login
///````````````````````````````````````````````````````````````````////////
app.get('/profile', authenticate, (req, res) => {
    res.send(req.rootUser)

})


//// code for logOut page ///
///`````````````````````````///
app.get('/logout', (req, res) => {

    console.log('logout page')
    res.cookie('userToken', 'userToken');
    res.clearCookie('userToken', { path: '/' })
    res.status(200).json({ succes: "logout successfully" })

})

//// for password reset ///
//``````````````````````//

app.use("/passwordReset", passwordReset);


///how to update email///
app.post('/updateEmail', async (req, res) => {

    var inventory = {
        email: req.body.email,
    };

    const { username, password, email } = req.body;

    const userExist = await User.findOne({ email: email });
    if (userExist) {
        console.log('i am here userexist');
        return res.status(401).json({ error: "email already exist" });
    }

    if ((!username) || (!email) || (!password)) {
        console.log('here 422');
        return res.status(422).json({ error: "please fill all the fields properly" })
    }
    const emailvalidator2 = require("email-validator");
    if (!(emailvalidator2.validate(email))) {
        return res.status(400).json({ error: 'Invalid Email' });
    }
    const userLogin = await User.findOne({ username });


    const isMatch = await bcrypt.compare(password, userLogin.password);
    if (!isMatch) {
        return res.status(400).json({ error: "password is wrong" });
    }


    try {

        User.findByIdAndUpdate(username, inventory, { new: true }, function (err, result) {
            if (err) {
                console.log(err);
            }
            console.log("RESULT: " + result);
            if (result == undefined) {
                return res.status(401).json({ error: 'username might be wrong' });

            }
            return res.status(200).json({ success: 'successfully updated' });
        })

    } catch (err) {
        console.log(`err in updateEmail server try -- ${err}`)
    }
})




app.listen(PORT, () => {
    console.log(`server is running at port ${PORT}`);
})