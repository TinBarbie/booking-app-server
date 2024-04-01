export const createHotel = async (req, res, next) => {
    const newHotel = new Hotel(req.body)
    try {
        const savedHotel = await newHotel.save()
        res.status(200).json(savedHotel)
    } catch (error) {
        next(error)
    }
}

export const updateHotel = async (req, res, next) => {
    try {
        const updatedHotel = await Hotel.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
        res.status(200).json(updatedHotel)
    } catch (error) {
        next(error)
    }
}
export const deleteHotel = async (req, res, next) => {
    try {
        await Hotel.findByIdAndDelete(req.params.id)
        res.status(200).json(`the hotel with id ${req.params.id} has been deleted`)
    } catch (error) {
        next(error)
    }
}
export const getHotelById = async (req, res, next) => {
    try {
        const hotel = await Hotel.findById(req.params.id)
        res.status(200).json(hotel)
    } catch (error) {
        next(error)
    }
}
export const getHotels = async (req, res, next) => {
    // const failed = true
    // if(failed) return next(createError(401, "You're not authenticated"))

    try {
        const hotels = await Hotel.find()
        res.status(200).json(hotels)
    } catch (error) {
        next(error)
    }
}