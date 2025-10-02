const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "A user must have a name"],
    minlength: 5,
    maxlength: 30,
  },
  email: {
    type: String,
    required: [true, "A user must have an email"],
    unique: true,
    lowercase: true,
    maxlength: 50,
    match: [/\S+@\S+\.\S+/, "Please enter a valid email"], // regex check
  },
  password: {
    type: String,
    required: [true, "A user must have a password"],
    minlength: 8,
    select: false, // don’t return password by default
  },
  passwordConfirm: {
    type: String,
    required: [true, "Please confirm your password"],
    validate: {
      // This only works on CREATE & SAVE
      validator: function (el) {
        return el === this.password;
      },
      message: "Passwords do not match!",
    },
  },
});

// 🔒 Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  // remove confirm field (not needed in DB)
  this.passwordConfirm = undefined;
  next();
});

// 🔑 Method to check password on login
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model("User", userSchema);
module.exports = User;
