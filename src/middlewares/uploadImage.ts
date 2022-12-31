import { Request } from 'express';
import multer, { FileFilterCallback } from 'multer';

// UPLOAD và đổi tên
// const upload = multer({ dest: process.cwd() + "/public/img" });
const storage = multer.diskStorage({
    // định nghĩa đường dẫn lưu file
    destination: (req, file, callback) => {
        callback(null, process.cwd() + '/public/img');
    },
    // đổi tên file upload (trước khi lưu file)
    filename: (_, file, callback) => {
        const fileName = Date.now() + '_' + file.originalname;
        callback(null, fileName);
    },
});

const fileFilter = (
    _: Request,
    file: Express.Multer.File,
    callback: FileFilterCallback
): void => {
    if (
        file.mimetype === 'image/png' ||
        file.mimetype === 'image/jpg' ||
        file.mimetype === 'image/jpeg' ||
        file.mimetype === 'image/webp'
    ) {
        callback(null, true);
    } else {
        callback(null, false);
    }
};

const uploadImage = multer({ storage, fileFilter });
export default uploadImage;
