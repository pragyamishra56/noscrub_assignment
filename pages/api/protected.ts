import { NextApiRequest, NextApiResponse } from 'next';
import { authMiddleware } from './middleware';

const handler = (req: NextApiRequest, res: NextApiResponse) => {
  res.status(200).json({ message: 'Protected content' });
};

export default authMiddleware(handler);
