import express from "express"
const rootRoute = express.Router()


// import middlewares
import usersController from "../controllers/usersController"
import tokenController from "../middlewares/basicToken"
import imagesRoute from "./imagesRoute"
rootRoute.post("/signup", usersController.signup)
rootRoute.post("/login", usersController.login)
rootRoute.use("/images", tokenController.verify, imagesRoute)
export default rootRoute;
