import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cookieParser from "cookie-parser"
import authRoute from './routes/auth.js';
import hotelsRoute from './routes/hotels.js';
import roomsRoute from './routes/rooms.js';
import usersRoute from './routes/users.js';
import redis from "redis";
// import twilio from 'twilio';

const app = express();
dotenv.config()

const connect = async () => {
    try {
        console.log(`trying connect to ${process.env.MONGO}`);
        await mongoose.connect(process.env.MONGO);
    } catch (error) {
        console.log("error connecting database");
        throw error;
    }
};

mongoose.connection.on("disconnected", () => {
    console.log("MongoDB disconnected!")
})

mongoose.connection.on("connected", () => {
    console.log("MongoDB connected!")
})

export const redisClient = redis.createClient()


redisClient.on('error', function (err) {
    console.log(err);
});
redisClient.on('connect', function (err) {
    console.log('Connected to redis successfully');
});

await redisClient.connect();

// const accountSid = process.env.TWILIO_ACCOUNT_SID; // Your Twilio account SID
// const authToken = process.env.TWILIO_AUTH_TOKEN; // Your Twilio auth token
// export const twilioClient = new twilio(accountSid, authToken);

//middlewares

app.use(cookieParser())
app.use(express.json())

app.use("/api/auth", authRoute)
app.use("/api/rooms", roomsRoute)
app.use("/api/hotels", hotelsRoute)
app.use("/api/users", usersRoute)

app.use((err, req, res, next) => {
    const errorStatus = err.status || 500;
    const errorMessage = err.message || "Something went wrong!"
    return res.status(errorStatus).json({
        success: false,
        status: errorStatus,
        message: errorMessage,
        stack: err.stack
    })
})

app.listen(process.env.APP_PORT, () => {
    connect()
    console.log(`Server start on port ${process.env.APP_PORT}!`)
});