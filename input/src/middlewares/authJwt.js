import jwt from 'jsonwebtoken';
import config from '../config'
import User from '../models/user';

export const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers['x-access-token'];

    if (!token) return res.json({ response: 'No token provided', success: false });
    const decoded = jwt.verify(token, config.SECRET); // informacion del usuario decodificada

    const user = await User.findById(decoded.id, { password: 0 }); // pasword: 0 es para que no retorne el password
    if (!user) return res.json({ response: 'no user token found', success: false });

    req.userData = user;
  } catch (error) {
    return res.status(500).json({ response: 'unauthorized', success: false });
  }

  next();
}