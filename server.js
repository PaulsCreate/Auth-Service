const dotenv = require("dotenv");

const http = require("http");
const { default: mongoose } = require("mongoose");

const app = require("./app");
dotenv.config({ path: "./config.env" });
const DB = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    // userNewUrlParser: true,
    // useCreateIndex: true,
    // useFindAndModify: false,
    // useUnifiedTopology: true,
  })
  .then((con) => {
    // console.log(con.connections);
    console.log("DB Connection Sucessfull");
  })
  .catch((err) => {
    console.log("DB Connection Failer", err);
  });

const port = process.env.PORT || 1000;
console.log("Running in:", process.env.NODE_ENV);


const server = app.listen(port, () => {
  console.log(`App running on port, ${port}`);
});
