import express from 'express';
const usersRoute = express.Router();

// import local controller
import usersController from '../controllers/usersController';

usersRoute.get('/', usersController.getUser);
usersRoute.get('/:id', usersController.getUserById);
usersRoute.get('/:id/images', usersController.getOwnedImages);
usersRoute.get('/:id/saved-images', usersController.getSavedImages);
usersRoute.put('/update', usersController.updateUser);

export default usersRoute;
