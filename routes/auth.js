import express from "express";
import { register, login, isValidToken, regenAccessToken, verifyUser } from "../controllers/auth.js";

const router = express.Router()

router.post("/register", register)
router.post("/login", login)
router.post('/isValidToken', isValidToken)
router.post('/regenAccessToken', regenAccessToken)
router.post('/verifyUser', verifyUser)


export default router