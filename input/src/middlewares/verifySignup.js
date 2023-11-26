import User from "../models/user"

export const checkDuplicateUsername = async (req, res, next) => {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (user) return res.json({ response: 'The user is already on use', success: false });

  next();
}

export const checkDuplicateEmail = async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (user) return res.json({ response: 'The email is already on use', success: false });

  next();
}