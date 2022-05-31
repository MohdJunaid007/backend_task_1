const mongoose = require('mongoose');
const { boolean } = require('webidl-conversions');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    lName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    cPassword: {
        type: String,
        required: true
    },
    status: {
        type: String,
        default: true
    },
    RegistrationDate: {
        type: String,
        // default:Date.now()
        default: new Date(Date.now()).toString()
    },
    ModifiedDate: {

        type: String,
        default: new Date(Date.now()).toString()

    },
    messages:[{
        email:{
            type:String,
            required:true
        },
        message:{
            type:String,
            required:true
        }
        
    }],
    tokens: [
        {
            token: {
                type: String,
                required: true
            }
        }
    ]
})




//=== we are hashing the password 

userSchema.pre('save', async function (next) {
    console.log("inside of hashing");
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 12); // 12 is number of rounds
    }
    next();
})

userSchema.pre('save', async function (next) {
    console.log("inside of cPassword hashing");
    if (this.isModified('cPassword')) {
        this.cPassword = await bcrypt.hash(this.cPassword, 12); // 12 is number of rounds
    }
    next();
})

// we are generating tokens

userSchema.methods.generateAuthToken = async function () {
    try {
        let token = jwt.sign({ _id: this._id }, process.env.SECRET_KEY);
        this.tokens = this.tokens.concat({ token: token });
        await this.save();
        return token;

    }
    catch (err) {
        console.log(err);
    }
}

userSchema.methods.addMessage=async function(email,message){
    try{
        this.messages= this.messages.concat({email,message})
        await this.save();
        return this.messages;


    }catch(err){
        console.log(`error in addElement part ${err}`)

    }
}



const User = mongoose.model('USER', userSchema);

module.exports = User;