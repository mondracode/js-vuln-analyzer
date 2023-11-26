import User from "../models/user";

export const getUsers = async (req, res) => {
  try {
    const users = await User.find();
    return res.json({ response: users, success: true });
  } catch (error) {
    res.json({ response: "Error getting users (" + error + ")", success: false });
  }
};

export const getUserByToken = async (req, res) => {
  try {
    res.json({ response: req.userData, success: true });
  } catch (error) {
    res.json({ response: "Error getting user (" + error + ")", success: false });
  }
};