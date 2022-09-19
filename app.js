require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./model/user");
const auth = require("./middleware/auth");
const admin = require("./middleware/admin")

const app = express();

app.use(express.json());


// requires a token
app.get("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
});

var roles = ["admin"];

// requires a token to authorize viewing of admin
app.get("/admin", admin(roles), (req, res) => {
  res.status(200).json("You are an admin");
});


// requires a token to authorize viewing of user details
app.get("/:id", auth, async (req, res) => {
    const {id} = req.params;
    const user = await User.findById(id).select('-__v').lean();
    res.status(200).json(user);
});

// requires a token to authorize deletion of user details
app.delete("/:id", auth, async (req, res) => {
    const {id} = req.params;
    const user = await User.findByIdAndDelete(id).select('-__v').lean();
    res.status(200).json(user);
});

// Register
app.post("/register", async (req, res) => {
    try {
        // Get user input
        const { first_name, last_name, email, password, role } = req.body;
    
        // Validate user input
        if (!(email && password && first_name && last_name && role)) {
          res.status(400).send("All input is required");
        }
    
        // check if user already exist
        // Validate if user exist in our database
        const oldUser = await User.findOne({ email });
    
        if (oldUser) {
          return res.status(409).send("User Already Exist. Please Login");
        }
    
        //Encrypt user password
        encryptedPassword = await bcrypt.hash(password, 10);
    
        // Create user in our database
        const user = await User.create({
            first_name,
            last_name,
            email: email.toLowerCase(), // sanitize: convert email to lowercase
            password: encryptedPassword,
            role,
        });
    
        // Create token
        const token = jwt.sign(
            { user_id: user._id, email, role },
            process.env.TOKEN_KEY,
            {
            expiresIn: "2h",
            }
        );
        // save user token
        user.token = token;
    
        // return new user
        res.status(201).json(user);
      } catch (err) {
        console.log(err);
      }
});
    
// Login
app.post("/login", async (req, res) => {
    try {
        // Get user input
        const { email, password } = req.body;
    
        // Validate user input
        if (!(email && password)) {
          res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email });
        const role = user.role
        if (user && (await bcrypt.compare(password, user.password))) {
          // Create token
          const token = jwt.sign(
            { user_id: user._id, email, role },
            process.env.TOKEN_KEY,
            {
              expiresIn: "2h",
            }
        );
    
          // save user token
          user.token = token;
    
          // user
          res.status(200).json(user);
        } else{
            res.status(401).send("Invalid Credentials");
        }
      } catch (err) {
        console.log(err);
      }
});

module.exports = app;