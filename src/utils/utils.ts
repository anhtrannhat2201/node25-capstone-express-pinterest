import { Request } from 'express';

// import prisma
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

const getFileUrl = (req: Request, dir: string, filename: string) => {
  const url = req.protocol + '://' + req.get('host') + dir + '/' + filename;
  return url;
};

export { getFileUrl };
