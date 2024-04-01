import express from "express";
import { createRoom, deleteRoom, getRoomById, getRooms, updateRoom } from "../controllers/room.js";
import {verifyAdmin} from '../utils/verifyToken.js'
const router = express.Router()

//CREATE
router.post('/:hotelid', verifyAdmin, createRoom)

//UPDATE
router.put('/:id', verifyAdmin, updateRoom)

//DELETE
router.delete('/:id/:hotelid', verifyAdmin, deleteRoom)

//GET A ROOM BY ID
router.get('/:id', getRoomById)

//GET ALL ROOMS
router.get('/', getRooms)

export default router