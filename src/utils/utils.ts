import { Request } from 'express';




const getFileUrl = (req: Request, dir: string, filename: string) => {
  const url = req.protocol + '://' + req.get('host') + dir + '/' + filename;
  return url;
};

export { getFileUrl };
