/**
 * Maintain DB Connection With Mongo Atlas With PoolSize
 * @author Malav Naagar
 * @copyright ABC
 * @version 1.0
 * @summary Connection File
 */

const mongoose = require("mongoose");
const dbOptions = {
  useNewUrlParser: true,
  //  poolSize:process.env.POOL_SIZE
};
mongoose.connect("mongodb://localhost:27017/task", dbOptions, (err) => {
  if (err) {
    console.log("DB Error", err);
  } else {
    console.log("Connected to DB");
  }
});

module.exports = mongoose;
