import User from "../models/user";

export const createUsers = async () => {
  try {
    const count = await User.estimatedDocumentCount();

    if (count > 0) return;

    const values = await Promise.all([
      new User({
        username: 'test',
        email: 'test@test.viio',
        password: await User.encryptPassword('test123')
      }).save()
    ]);
  } catch (error) {
    console.log(error);
  }
}