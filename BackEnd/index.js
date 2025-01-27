require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");
const passport = require("passport");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");

const PORT = 8080;

const app = express();

app.use(express.json()); // Use this to parse incoming JSON data

// Enable CORS
app.use(cors({
  origin: process.env.FRONTEND_DOMAIN,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
}));

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.authToken;

  if (!token) {
    return res.status(401).json({ error: "Login Required" });
  }

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or Expired Token" });
    }
    req.user = user; // Attach decoded user to the request object
    next();
  });
};

// Google OAuth Authentication
app.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/google/callback", passport.authenticate("google", {
  failureRedirect: process.env.FRONTEND_DOMAIN,
}), (req, res) => {
  if (req.user) {
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Only set secure cookies in production
      maxAge: 3600000, // 1 hour expiry
      sameSite: 'strict', // Ensure the cookie is sent only to the same site
    });
    res.redirect(`${process.env.FRONTEND_DOMAIN}/Home`);
  } else {
    res.redirect(process.env.FRONTEND_DOMAIN);
  }
});

// Facebook OAuth Authentication
app.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

app.get("/facebook/callback", passport.authenticate("facebook", {
  failureRedirect: process.env.FRONTEND_DOMAIN,
  successRedirect: `${process.env.FRONTEND_DOMAIN}/Home`,
}));

// Register a new user
app.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newAuth = new authModel({ userName, email, password: hashedPassword });

  try {
    const user = await authModel.findOne({ email });
    if (user) return res.json("Already Registered");

    const savedUser = await newAuth.save();
    res.send(savedUser);
  } catch (err) {
    res.status(400).send(err);
  }
});

// Local Login Route
app.post("/login", passport.authenticate("local", {
  failureRedirect: process.env.FRONTEND_DOMAIN,
}), (req, res) => {
  // On successful login, generate JWT token
  const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
  res.cookie('authToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 3600000,
    sameSite: 'strict',
  });
  res.json({ success: "successfully logged in" });
});

// Logout
app.get("/logout", (req, res) => {
  res.clearCookie('authToken');
  res.json({ success: "logged out" });
});

// Get current user data
app.get("/getUser", authenticateJWT, (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401).json({ error: "Not logged in" });
  }
});

// Forgot Password
app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  const user = await authModel.findOne({ email });

  if (!user) return res.send({ Status: "Enter a valid email" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: "1d" });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject: "Reset Password for Task Manager",
    text: `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.log(error);
      res.status(500).send({ Status: "Error sending email" });
    } else {
      res.send({ Status: "success" });
    }
  });
});

// Password Reset (Update password after verification)
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;

  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err) => {
    if (err) return res.send({ Status: "Invalid or Expired Token" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    authModel.findByIdAndUpdate(id, { password: hashedPassword })
      .then(() => res.send({ Status: "Password updated successfully" }))
      .catch((err) => res.send({ Status: err }));
  });
});

// Protect Routes with JWT Authentication Middleware
app.use("/todo", [authenticateJWT, TodoRoutes]);
app.use("/note", [authenticateJWT, NoteRoutes]);
app.use("/task", [authenticateJWT, TaskRoutes]);

// Start server
app.listen(PORT, () => {
  console.log(`Server Running On Port : ${PORT}`);
});

module.exports = app;
