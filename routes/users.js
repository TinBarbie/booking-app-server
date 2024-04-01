import express from "express";
import { deleteUser, getUserById, getUsers, updateUser } from "../controllers/user.js";
import { verifyAdmin, verifyToken, verifyUser } from "../utils/verifyToken.js";

const router = express.Router()

router.get('/checkauthentication', verifyToken, (req, res, next) => {
    res.send("hello user, you are logged in")
})

router.get('/checkuser/:id', verifyUser, (req, res, next) => {
    res.send("hello user, you are logged in and you can delete your account")
})

router.get('/checkadmin/:id', verifyAdmin, (req, res, next) => {
    res.send("hello admin, you are logged in and you can delete all accounts")
})

//UPDATE
router.put('/:id', verifyUser, updateUser)

//DELETE
router.delete('/:id', verifyUser, deleteUser)

//GET A USER BY ID
router.get('/:id', verifyUser, getUserById)

//GET ALL USERS
router.get('/', verifyAdmin, getUsers)


export default router