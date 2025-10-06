const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const AppError = require('../utils/appError');
const Email = require('../utils/email');
const crypto = require('crypto');

// Helper: sign JWT
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

// Helper: send token in response
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // remove password field from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

// SIGNUP
exports.signup = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      role: req.body.role,
    });

    createSendToken(newUser, 201, res);
  } catch (err) {
    next(new AppError(err.message, 400));
  }
};

// LOGIN
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // 1) Check email & password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }

    // 2) Find user & check password
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    // 3) Send token
    createSendToken(user, 200, res);
  } catch (err) {
    next(new AppError(err.message, 400));
  }
};

// PROTECT middleware
exports.protect = async (req, res, next) => {
  try {
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return next(
        new AppError('You are not logged in! Please log in to get access.', 401)
      );
    }

    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // find user by id
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError('The user belonging to this token no longer exists.', 401)
      );
    }

    req.user = currentUser;
    next();
  } catch (err) {
    next(new AppError(err.message, 401));
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // Check if user's role is in the allowed roles
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  };
};

exports.forgotPassword = async (req, res, next) => {
  try {
    //(1) Find user based on POSTED email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return next(
        new AppError('There is no user with that email address.', 404)
      );
    }

    // (2) Generate a Reset Token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // (3) Send Reset token to mail
    const resetURL = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/auth/resetPassword/${resetToken}`;

    try {
      await new Email(user, resetURL).sendPasswordReset();

      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!',
      });
    } catch (err) {
      console.error('❌ Email sending failed:', err);

      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      const message =
        process.env.NODE_ENV === 'development'
          ? `Email sending failed: ${err.message}`
          : 'There was an error sending the email. Try again later!';

      return next(new AppError(message, 500));
    }
  } catch (err) {
    next(new AppError(err.message, 400));
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    // 1) Get user based on the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // 3) Log the user in, send JWT
    createSendToken(user, 200, res);
  } catch (err) {
    next(new AppError(err.message, 400));
  }
};

exports.deleteUser = async (req, res, next) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.status(204).json({
      status: 'success',
      data: null,
    });
  } catch (err) {
    next(new AppError(err.message, 400));
  }
};
