const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const auth = require("../auth/auth")
router.get("/all-users",auth, (req, res) => {
  res.send("users Here");
});

router.post("/sign-up", async (req, res) => {
  try {
    const { email, password ,age} = req.body;
    let isUser = await User.findOne({ email });
    if (isUser) {
      res.status(401).json({ message: "Email already in use" });
      return;
    }

    if (password.length < 8) {
      res
        .status(401)
        .json({ message: "Required Password must be atleast 8 characters long" });
      return;
    }
    const saltrounds = 10;

    let hash = await bcrypt.hash(password, saltrounds);
   
    let user = new User({
      email: email,
      password: hash,
      age: age
    });
    let user_resp = await user.save();
    user_resp = user_resp.toObject()

    const token = jwt.sign(
      {
        user_id: user_resp._id,
        email,
      },
      process.env.JWT_TOKEN,
      {
        expiresIn: "1h",
      }
    );

    // console.log(token);

    user_resp.token = token;

    console.log({ user_resp });
    res.status(201).json({user_resp});
  } catch (err) {
    res.status(400).json(err);
  }
});

router.post("/sign-in", async (req, res) => {
  try {
    const { email, password } = req.body;
    let user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Credentials Invalid" });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {

        const token = jwt.sign(
            {
              user_id: user._id,
              email,
            },
            process.env.JWT_TOKEN,
            {
              expiresIn: "1h",
            }
          );
          user = user.toObject()
        user.token = token
        return res.status(200).json({ message: "Logged in", data:user });
      }

      console.log(err);
      return res.status(401).json({ message: "Invalid Credentials" });
    });
  } catch (err) {
    res.status(401).json(err);
  }
});

module.exports = router;
