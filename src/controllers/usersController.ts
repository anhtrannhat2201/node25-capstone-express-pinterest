import { PrismaClient } from "@prisma/client";
import { Request, Response } from "express";
import responseCode, { catchError } from "../config/responses";
import validators from "../validation/validators";
import bcrypt from 'bcrypt';
import { Secret } from 'jsonwebtoken';

const secretKey: Secret = process.env.SECRET_KEY!;
const secretCookie: Secret = process.env.SECRET_COOKIE!;

import tokenController from "../middlewares/basicToken";
import generalConstant from '../constants/generalConstants';

// jwt config

const prisma = new PrismaClient()

const usersController = {
    // Đăng ký
    signup: async (req: Request, res: Response) => {
        try {
            const newUser = await validators.createUser().validateAsync(req.body,
                {
                    stripUnknown: true,
                })
            const checkEmail = await prisma.nguoi_dung.findFirst({
                where: { email: newUser.email }
            })
            if (checkEmail) {
                responseCode.conflict(
                    res,
                    { email: newUser.email },
                    "Email đã tồn tại"
                );
                return;
            }
            newUser.mat_khau = bcrypt.hashSync(
                newUser.mat_khau,
                Number(process.env.BCRYPT_SALT)
            )
            await prisma.nguoi_dung.create({ data: newUser })
            responseCode.created(res, "Success", "Đăng ký thành công")
        } catch (error) {
            catchError(error, req, res)

        }
    },
    // Đăng nhập
    login: async (req: Request, res: Response) => {
        try {
            const loginInfo = await validators.login.validateAsync(req.body, {
                stripUnknown: true,
            });

            const user = await prisma.nguoi_dung.findFirst({
                where: {
                    email: loginInfo.email,
                },
            });
            if (!user) {
                responseCode.unauthorized(
                    res,
                    'Đăng nhập thất bại',
                    'Email hoặc mật khẩu không đúng'
                );
                return;
            }

            const checkPass = bcrypt.compareSync(loginInfo.mat_khau, user.mat_khau);
            if (!checkPass) {
                responseCode.unauthorized(
                    res,
                    'Đăng nhập thất bại',
                    'Email hoặc mật khẩu không đúng'
                );
                return;
            }
            const authtoken = tokenController.create(user, secretKey);
            const cookietoken = tokenController.create(user, secretCookie);


            res
                .status(200)
                .cookie(generalConstant.SECRET_COOKIE, cookietoken, {
                    // secure: true,
                    httpOnly: true,
                    sameSite: 'none',
                    maxAge: 2592000000,
                })
                .json({ message: 'Đăng nhập thành công', content: { authtoken } });
        } catch (error) {
            catchError(error, req, res);
        }
    },
    logout: (req: Request, res: Response) => {
        try {
            res
                .status(200)
                .clearCookie(generalConstant.SECRET_COOKIE)
                .json({
                    message: 'Đăng xuất thành công',
                    content: { status: 'Logged Out' },
                });
        } catch (err) {
            responseCode.error(res, 'Lỗi Backend');
        }
    },
    getUser: async (_: Request, res: Response) => {
        try {
            const usersList = await prisma.nguoi_dung.findMany({
                select: {
                    nguoi_dung_id: true,
                    email: true,
                    ho_ten: true,
                    tuoi: true,
                    anh_dai_dien: true,
                },
            });
            responseCode.success(res, usersList, 'Lấy thông tin user thành công');
        } catch (err) {
            responseCode.error(res, 'Lỗi Backend');
        }
    },
    // LẤY thông tin user theo ID
    getUserById: async (req: Request, res: Response) => {
        try {
            const id = await validators.isNumber.validateAsync(
                Number(req.params.id),
                { messages: { 'number.base': 'nguoi_dung_id phải là dạng số' } }
            );

            const user = await prisma.nguoi_dung.findFirst({
                where: { nguoi_dung_id: id },
                select: {
                    nguoi_dung_id: true,
                    email: true,
                    ho_ten: true,
                    tuoi: true,
                    anh_dai_dien: true,
                },
            });

            if (!user) {
                return responseCode.notFound(
                    res,
                    { nguoi_dung_id: id },
                    'Người dùng không tồn tại'
                );
            }
            responseCode.success(res, user, 'Lấy thông tin người dùng thành công');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    // LẤY danh sách hình ảnh được User tạo
    getOwnedImages: async (req: Request, res: Response) => {
        try {
            const id = await validators.isNumber.validateAsync(
                Number(req.params.id),
                { messages: { 'number.base': 'nguoi_dung_id phải là dạng số' } }
            );

            const imagesList = await prisma.hinh_anh.findMany({
                where: { nguoi_dung_id: id },
            });

            responseCode.success(res, imagesList, 'Lấy danh sách ảnh thành thông');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    // LẤY danh sách hình ảnh được User Saved
    getSavedImages: async (req: Request, res: Response) => {
        try {
            const id = await validators.isNumber.validateAsync(
                Number(req.params.id),
                { messages: { 'number.base': 'nguoi_dung_id phải là dạng số' } }
            );

            const imagesList = await prisma.hinh_anh.findMany({
                where: {
                    luu_anh: {
                        some: { nguoi_dung_id: id },
                    },
                },
            });

            responseCode.success(res, imagesList, 'Lấy danh sách ảnh thành thông');
        } catch (err) {
            catchError(err, req, res);
        }
    },
    // CẬP NHẬT thông tin User
    updateUser: async (req: Request, res: Response) => {
        try {
            const userInfo = await validators.user().validateAsync(req.body, {
                stripUnknown: true,
            });

            userInfo.mat_khau = bcrypt.hashSync(
                userInfo.mat_khau,
                Number(process.env.BCRYPT_SALT)
            );
            const result = await prisma.nguoi_dung.update({
                where: { nguoi_dung_id: userInfo.nguoi_dung_id },
                data: userInfo,
                select: {
                    nguoi_dung_id: true,
                    email: true,
                    ho_ten: true,
                    tuoi: true,
                    anh_dai_dien: true,
                },
            });

            responseCode.success(res, result, 'Cập nhật user thành công');
        } catch (err) {
            catchError(err, req, res);
        }
    },
}
export default usersController