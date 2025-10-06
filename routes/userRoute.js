const express = require("express");
const userController = require("../controllers/userController");
const authController = require("../controllers/authController");

const router = express.Router();

router.get(
  "/getAllUsers", authController.protect,
  authController.restrictTo("admin"),
  userController.getAllUsers
);

module.exports = router;
