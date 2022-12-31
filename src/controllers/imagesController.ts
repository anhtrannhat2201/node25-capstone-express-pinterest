import "dotenv/config"

// import prisma
import { PrismaClient } from "@prisma/client"
const prisma = new PrismaClient()

// import local config 
import responseCode, { catchError } from "../config/responses"
// import validation
import validators from "../validation/validators"

// import local utils
import { getFileUrl } from "../utils/utils"
import { Request, Response } from "express"
const imagesController = {
    getImages: async (req: Request, res: Response) => {
        try {
            const imagesData = await prisma.hinh_anh.findMany()
            responseCode.success(res, imagesData, "Lấy danh sách ảnh thành công")
        } catch (error) {
            responseCode.error(res, "Lỗi Backend")
        }
    },
    getImagesByName: async (req: Request, res: Response) => {
        try {
            const { name } = req.params;
            const imagesData = await prisma.hinh_anh.findMany({
                where: { ten_hinh: { contains: name } },
            });

            responseCode.success(res, imagesData, 'Lấy danh sách ảnh thành công');
        } catch (err) {
            responseCode.error(res, 'Lỗi Backend');
        }
    },
    // XÓA ảnh theo ID
    deleteImage: async (req: Request, res: Response) => {
        try {
            const id = await validators.isNumber.validateAsync(
                Number(req.params.id),
                { messages: { 'number.base': 'hinh_id phải là kiểu số' } }
            );

            const result = await prisma.hinh_anh.delete({ where: { hinh_id: id } });
            responseCode.success(res, result, 'Xóa hình thành công');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    isImageSaved: async (req: Request, res: Response) => {
        try {
            const { id, userid } = req.params;

            const savedImgData = await prisma.luu_anh.findFirst({
                where: {
                    hinh_id: Number(id),
                    nguoi_dung_id: Number(userid),
                },
            });

            responseCode.success(
                res,
                { isSaved: savedImgData ? true : false },
                'Success'
            );
        } catch (err) {
            responseCode.error(res, 'Lỗi Backend');
        }
    },
    // LẤY thông tin ảnh theo ID
    getImagesById: async (req: Request, res: Response) => {
        try {
            const id = await validators.isNumber.validateAsync(
                Number(req.params.id),
                { messages: { 'number.base': 'hinh_id phải là kiểu số' } }
            );

            const imageInfo = await prisma.hinh_anh.findFirst({
                where: { hinh_id: id },
                include: {
                    nguoi_dung: {
                        select: {
                            nguoi_dung_id: true,
                            email: true,
                            ho_ten: true,
                            tuoi: true,
                            anh_dai_dien: true,
                        },
                    },
                },
            });

            if (!imageInfo) {
                responseCode.notFound(res, { id }, 'Không tìm thấy hình ảnh');
                return;
            }
            responseCode.success(res, imageInfo, 'Lấy thông tin ảnh thành công');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    createImage: async (req: Request, res: Response) => {
        try {
            const newImage = await validators.image.validateAsync(req.body, {
                abortEarly: true,
                stripUnknown: true,
            });

            const result = await prisma.hinh_anh.create({ data: newImage });
            responseCode.created(res, result, 'Tạo hình ảnh thành công');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    // UPLOAD ảnh
    uploadImage: async (req: Request, res: Response) => {
        try {
            if (!req.file) {
                responseCode.badRequest(
                    res,
                    '',
                    'Định dạng file không hợp lệ. Phải là png/jpg/jpeg/webp'
                );
                return;
            }
            responseCode.success(
                res,
                {
                    imageURL: getFileUrl(req, process.env.IMAGE_URL!, req.file.filename),
                },
                'Upload file thành công'
            );
        } catch (err) {
            catchError(err, req, res);
        }
    },
}
export default imagesController