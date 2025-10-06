const User = require("../models/userModel");

exports.getAllUsers = async (req, res, next) => {
  try {
    const user = await User.find();

    res.status(200).json({
      status: "Success",
      result: user.length,
      data: {
        user,
      },
    });
  } catch (err) {
    next(err);
  }
};
