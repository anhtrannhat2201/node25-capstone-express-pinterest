import { PrismaClient } from "@prisma/client";
import { Request, Response } from "express";
import responseCode, { catchError } from "../config/responses";
import validators from "../validation/validators";
import bcrypt from 'bcrypt';
import { Secret } from 'jsonwebtoken';

const secretKey: Secret = process.env.SECRET_KEY!;
import tokenController from "../middlewares/basicToken";

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
                    'Login failed',
                    'Email hoặc mật khẩu không đúng'
                );
                return;
            }

            const checkPass = bcrypt.compareSync(loginInfo.mat_khau, user.mat_khau);
            if (!checkPass) {
                responseCode.unauthorized(
                    res,
                    'Login failed',
                    'Email hoặc mật khẩu không đúng'
                );
                return;
            }
            const authtoken = tokenController.create(user, secretKey);


            res.status(200).json({
                message: 'Đăng nhập thành công',
                content: { authtoken }
            });

        } catch (error) {
            catchError(error, req, res);

        }
    }
}
export default usersController