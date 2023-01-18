const userOperations = require("../services/userService");
const User = require("../dto/userdto");
const bcrypt = require("../utils/encrypt");
const token = require("../utils/token");

//User Registration
const register = (req, res) => {
  let hashPassword = bcrypt.doEncrypt(req.body.password);
  const user = new User(
    req.body.name,
    hashPassword,
    req.body.phone,
    req.body.email
  );
  const promise = userOperations.addUser(user);
  promise
    .then((data) => {
      res.status(201).json({
        message: "Registration Successfully",
        data: data,
      });
    })
    .catch((err) => {
      res.status(500).json(err.message);
    });
};
//User Login With JWT and Encrypt Password
const loginUser = async (req, res) => {
  let data;
  let email = req.body.email;
  let password = req.body.password;
  let user = await userOperations.login(email);
  if (user) {
    let pass = bcrypt.compare(password, user.password);
    if (pass) {
      const { password, ...others } = user._doc;
      const accessToken = token.createToken({
        id: user._id,
        isAdmin: user.isAdmin,
      });
      user = {
        _id: user._id,
        accessToken,
        fullName: user.name,
        lastUpdate: new Date(),
        name: user.name,
      };
      data = {
        data: { user },
        setting: {
          success: 1,
          message: `Welcome ${user && user.name}`,
        },
      };
    } else {
      data = {
        data: undefined,
        settings: {
          success: 0,
          message: `Password Not Match`,
        },
      };
    }
  } else {
    data = {
      data: undefined,
      settings: {
        success: 0,
        message: `User not found!`,
      },
    };
  }
  return res.status(200).json({ message: data });
};
module.exports = { register, loginUser };
