import mongoose, {Schema} from "mongoose";
import jwt  from "jsonwebtoken";
import bcrypt from "bcrypt";


const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowcase: true,
            trim: true,
            index: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowcase: true,
            trim: true, 
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true  
        },
        avatar: {
            type: String, // cloudinary url
            required:true
        },
        coverIamge: {
            type: String // cloudinary url
        },
        watchHistory: {
            type: Schema.Types.ObjectId,
            ref: "Video"
        },
        password: {
            type: String,
            required: [true, 'Password is required']
        },
        refreshToken: {
            type: String
        }
    },
    {
         timestamps: ture
    }
    )

    // pre Hook -> pre middleware function are executed one after another, when each middleware calls next

    userSchema.pre("save", async function (next) {

        if(!this.isModified("password")) return next();

        this.password = bcrypt.hash(this.password, 10)
        next()
    })

    userSchema.methods.isPasswordCorrect = async function
    (password){
        // check using bcrypt
        return await bcrypt.compare(password, this.password)
    }

    // jwt is a bearer token

    userSchema.methods.generateAccessToken = function (){
        jwt.sign(
            {
                _id: this._id,
                email: this.email,
                username: this.username,
                fullName: this.fullName
            },
            process.env.ACCESS_TOKEN_SECRET,
            {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY
            }
        )
    }

    userSchema.methods.generateRefreshToken = function (){
        jwt.sign(
            {
                _id: this._id,
                email: this.email,
                username: this.username,
                fullName: this.fullName
            },
            process.env.REFRESH_TOKEN_SECRET,
            {
                expiresIn: process.env.REFRESH_TOKEN_EXPIRY
            }
        )
    }

    userSchema.methods.generateRefreshToken = function (){}


export const User = mongoose.model("User", userSchema)