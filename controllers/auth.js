import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";
import otpGenerator from 'otp-generator';
import { redisClient } from "../index.js";

var refreshTokens = {};

export const register = async (req, res, next) => {
    const { username, email, password, phoneNumber } = req.body;

    const otp = otpGenerator.generate(4, {
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars: false,
    });

    if (!username || !email || !password || !phoneNumber) {
        return res.status(400).send("Missing some params. Please try again with full required params.")
    }
    let existUsername = await User.findOne({ username });
    if (existUsername) {
        return res.status(400).send("Username is duplicated!")
    }
    let existEmail = await User.findOne({ email });
    if (existEmail) {
        return res.status(400).send("Email is duplicated!")
    }
    let existPhoneNumber = await User.findOne({ phoneNumber });
    if (existPhoneNumber) {
        return res.status(400).send("phone number is duplicated!")
    }

    const salt = bcrypt.genSaltSync(10);
    bcrypt.hash(password, salt).then(hashedPassword => {

        const user = new User({
            username,
            email,
            phoneNumber,
            password: hashedPassword
        })

        redisClient.set(phoneNumber, otp);

        const { password, ...responseUser } = user._doc;
        // return save result as a response
        user.save()
            .then(result => res.status(201).send({
                msg: "User Register Successfully",
                OTP: otp, User: responseUser
            }))
            .catch(error => res.status(500).send({ error }))
    })
}

export async function verifyUser(req, res, next) {
    const { username, phoneNumber, otp } = req.body;

    // check the user existance
    let exist = await User.findOne({ username: username });
    if (!exist) return res.status(404).send({ error: "Can't find User!" });

    let existPhoneNumber = await User.findOne({ phoneNumber });
    if (!existPhoneNumber) {
        return res.status(400).send("Can't find Phone number!")
    }

    // Retrieve the stored OTP from Redis, using the user's email as the key
    const storedOTP = await redisClient.get(phoneNumber);

    if (storedOTP === otp) {
        // If the OTPs match, delete the stored OTP from Redis
        redisClient.del(phoneNumber);

        // Update the user's isVerified property in the database
        await User.findOneAndUpdate({ username }, { isVerified: true });

        // Send a success response
        return res.status(200).json({
            status: 'OTP verified successfully',
            username,
            isVerified: true
        });
    } else {
        // If the OTPs do not match, send an error response
        return res.status(400).send('Invalid OTP');
    }
}

export const login = async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return next(createError(400, "Username and password are required!"))
    }
    const user = await User.findOne({ username: req.body.username })
    if (!user) return next(createError(404, "User not found!"))
    const isCorrectPassword = await bcrypt.compare(req.body.password, user.password)
    if (!isCorrectPassword) return next(createError(400, "Wrong password"))

    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.JWT, { expiresIn: process.env.ACCESS_TOKEN_LIFE })
    const refreshToken = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.JWT, { expiresIn: process.env.REFRESH_TOKEN_LIFE })

    const response = {
        "status": "Logged in",
        "accessToken": token,
        "refreshToken": refreshToken,
    }

    refreshTokens[refreshToken] = response

    return res.json(response)
}

export const regenAccessToken = async (req, res, next) => {
    const { refreshToken, id, isAdmin } = req.body
    console.log(refreshTokens);
    console.log(refreshToken, id, isAdmin);
    if (!refreshToken || !id) {
        return res.status(400).send('refresh token and id and isAdmin are required!')
    }
    if (!(refreshToken in refreshTokens)) {
        return res.status(403).send('Invalid refresh token!')
    }
    const token = jwt.sign({ id, isAdmin }, process.env.JWT, { expiresIn: process.env.ACCESS_TOKEN_LIFE })
    refreshTokens[refreshToken].token = token
    res.status(200).json({
        "status": "Successfully regenerating access token!",
        "newAccessToken": token,
    })
}

export const isValidToken = async (req, res, next) => {
    const accessToken = req.get('accessToken');
    if (!accessToken) {
        return next(createError(400, "Access token is required in Header!"))
    }
    jwt.verify(accessToken, process.env.JWT, function (error, decoded) {
        if (error) {
            return res.status(403).json(error);
        } else {
            return res.status(200).send("Access token is super valid!")
        }

    });
}