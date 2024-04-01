import express from "express";
import { createHotel, deleteHotel, getHotelById, getHotels, updateHotel } from "../controllers/hotel.js";
import {verifyAdmin} from "../utils/verifyToken.js"

const router = express.Router()

//CREATE
router.post('/', verifyAdmin, createHotel)

//UPDATE
router.put('/:id', verifyAdmin, updateHotel)

//DELETE
router.delete('/:id', verifyAdmin, deleteHotel)

//GET A HOTEL BY ID
router.get('/:id', getHotelById)

//GET ALL HOTELS
router.get('/', getHotels)


export default router