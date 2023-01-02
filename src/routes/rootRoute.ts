import express from "express"
const rootRoute = express.Router()

import usersRoute from './usersRoute';
import commentsRoute from './commentsRoute';

// import middlewares
import usersController from "../controllers/usersController"
import tokenController from "../middlewares/basicToken"
import imagesRoute from "./imagesRoute"
rootRoute.post("/signup", usersController.signup)
rootRoute.post("/login", usersController.login)
rootRoute.post('/logout', usersController.logout);
rootRoute.use("/images", tokenController.verify, imagesRoute)
rootRoute.use('/users', tokenController.verify, usersRoute);
rootRoute.use('/comments', tokenController.verify, commentsRoute);
export default rootRoute;
