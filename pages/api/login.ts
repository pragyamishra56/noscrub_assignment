import { NextApiRequest, NextApiResponse } from 'next';
import { encode_jwt } from 'jwt-library'; // Make sure jwt-library is linked properly

export default (req: NextApiRequest, res: NextApiResponse) => {
  const token = encode_jwt('your-secret-key', 'user-id', { role: 'user' }, 3600);
  res.status(200).json({ token });
};
