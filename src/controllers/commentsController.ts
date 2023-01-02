import { Request, Response } from 'express';

// import prisma
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

// import local config
import responseCode, { catchError } from '../config/responses';

// import local utils
import validators from '../validators/validators';

const commentsController = {
  // LẤY danh sách bình luận theo ID ảnh
  getCommentsByImgId: async (req: Request, res: Response) => {
    try {
      const id = await validators.isNumber.validateAsync(
        Number(req.params.id),
        { messages: { 'number.base': 'hinh_id phải là kiểu số' } }
      );

      const commentsData = await prisma.binh_luan.findMany({
        where: { hinh_id: id },
      });

      responseCode.success(
        res,
        commentsData,
        'Lấy thông tin bình luận thành công'
      );
    } catch (err) {
      catchError(err, req, res);
    }
  },

  // (POST) LƯU thông tin bình luận của người dùng
  postComment: async (req: Request, res: Response) => {
    try {
      const commentInfo = await validators.comment.validateAsync(req.body, {
        abortEarly: true,
        convert: false,
        stripUnknown: true,
      });
      const postComment = await prisma.binh_luan.create({ data: commentInfo });
      responseCode.created(res, postComment, 'Đăng bình luận thành công');
    } catch (err) {
      catchError(err, req, res);
    }
  },
};

export default commentsController;
