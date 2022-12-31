import { NextFunction, Request, Response } from 'express';
import 'dotenv/config';

// import jwt token
import jwt, { JsonWebTokenError, Secret } from 'jsonwebtoken';

// import local config
import responseCode from '../config/responses';

// jwt config

const secretKey: Secret = process.env.SECRET_KEY!;

const tokenController = {
  create: (data: any, secret: string): string => {
    const token = jwt.sign(data, secret, {
      algorithm: 'HS256',
      expiresIn: '30d',
    });
    return token;
  },
  check: (
    token: string,
    secret: string
  ): { checkData: boolean; message: string } => {
    try {
      jwt.verify(token, secret);
      return { checkData: true, message: '' };
    } catch (err) {
      if (err instanceof JsonWebTokenError) {
        return { checkData: false, message: err.message };
      }
      return {
        checkData: false,
        message: 'Failed at Token Verification',
      };
    }
  },
  verify: (req: Request, res: Response, next: NextFunction): void => {
    try {
      const authtoken = req.header('authtoken');

      if (!authtoken) {
        responseCode.unauthorized(res, 'Unauthorized', 'Token không hợp lệ');
        return;
      }

      const verifyToken = tokenController.check(authtoken, secretKey);

      if (verifyToken.checkData) {
        next();
        return;
      }

      responseCode.unauthorized(res, 'Unauthorized', 'Token không hợp lệ');
    } catch (err) {
      responseCode.error(res, 'Lỗi Backend');
    }
  },
};

export default tokenController;
