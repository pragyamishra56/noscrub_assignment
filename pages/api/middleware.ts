import { NextApiRequest, NextApiResponse } from 'next';
import { validate_jwt } from 'jwt-library'; // Make sure jwt-library is linked properly

export function authMiddleware(handler) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token || !validate_jwt('your-secret-key', token)) {
      return res.status(401).send('unauthorized');
    }
    return handler(req, res);
  };
}
