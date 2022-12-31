import { Request, Response } from 'express';

// import Joi validator
import Joi from 'joi';

// import interfaces
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

const responseCode = {
  success: (res: Response, data: any, message: string) => {
    res.status(200).json({
      message,
      content: data,
    });
  },
  created: (res: Response, data: any, message: string) => {
    res.status(201).json({
      message,
      content: data,
    });
  },
  badRequest: (res: Response, data: any, message: string) => {
    res.status(400).json({
      message,
      content: data,
    });
  },
  unauthorized: (res: Response, data: any, message: string) => {
    res.status(401).json({
      message,
      content: data,
    });
  },
  notFound: (res: Response, data: any, message: string) => {
    res.status(404).json({
      message,
      content: data,
    });
  },
  conflict: (res: Response, data: any, message: string) => {
    res.status(409).json({
      message,
      content: data,
    });
  },
  error: (res: Response, message: string) => {
    res.status(500).send(message);
  },
};

export const catchError = (err: unknown, req: Request, res: Response) => {
  if (err instanceof Joi.ValidationError) {
    responseCode.badRequest(res, '', err.details[0].message);
    return;
  }
  if (err instanceof PrismaClientKnownRequestError) {
    responseCode.badRequest(
      res,
      err.meta ? err.meta : req.body,
      'Bad Request. Please check the request data.'
    );
    return;
  }
  responseCode.error(res, 'Lỗi Backend');
};

export default responseCode;
