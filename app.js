const dotenv = require("dotenv").config();
const express = require("express");
const authRoute = require("./routes/authRoute");
const userRoute = require("./routes/userRoute");

const app = express();

app.use(express.json());

app.use("/api/v1/auth", authRoute);
app.use("/api/v1/users", userRoute);

module.exports = app;

// app.request();
