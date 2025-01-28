require("./passport");
require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");
const PORT = 8080;

const app = express();
// Middleware to parse JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // If you use URL-encoded forms

app.use(
  cors({
    origin: "https://task-manager-app-six-phi.vercel.app", // Replace with your frontend domain
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"], // Allowed methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
  })
);

app.options("*", cors());
app.use((req, res, next) => {
  console.log("Incoming Request:");
  console.log("Origin:", req.headers.origin);
  console.log("Method:", req.method);
  console.log("Headers:", req.headers);
  next();
});



// MongoDB session store
const sessionStore = new MongoStore({
  mongoUrl: process.env.MONGO_URL,
  collectionName: "session",
});
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Strong, secure key
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // Set true for HTTPS in production
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      sameSite: "none"
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get("/", (req, res) => {
  res.json({ message: "Server is running" });
});

app.post("/register",cors(), async (req, res) => {
  console.log("Headers:", req.headers);
  console.log("Body:", req.body);
  const { userName, email, password } = req.body;
  try {
    const userExists = await authModel.findOne({ email });
    if (userExists) return res.status(400).json({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAuth = new authModel({ userName, email, password: hashedPassword });
    const savedUser = await newAuth.save();
    res.status(201).json({ user: savedUser });
  } catch (err) {
    res.status(500).json({ error: "Registration failed", details: err.message });
  }
});

// Google Authentication
app.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_DOMAIN}/Home`);
  }
);

// Facebook Authentication
app.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

app.get(
  "/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_DOMAIN}/Home`);
  }
);

// Local Login
app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/" }),
  (req, res) => {
    res.json({ message: "Successfully logged in", user: req.user });
  }
);

// Logout
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: "Logout failed", details: err.message });
    res.json({ message: "Successfully logged out" });
  });
});

// Get User
app.get("/getUser", (req, res) => {
  if (req.isAuthenticated()) {
    res.json(req.user);
  } else {
    res.status(401).json({ error: "User not authenticated" });
  }
});

// Forgot Password
app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await authModel.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: "1d" });
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `${process.env.FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset",
      text: `Reset your password: ${resetLink}`,
    });

    res.json({ message: "Password reset email sent" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send password reset email", details: err.message });
  }
});

// Reset Password
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    if (decoded.id !== id) return res.status(400).json({ message: "Invalid token" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await authModel.findByIdAndUpdate(id, { password: hashedPassword });
    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(400).json({ error: "Invalid or expired token", details: err.message });
  }
});

// Authentication middleware
const authenticator = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
};

// Secured Routes
app.use("/todo", authenticator, TodoRoutes);
app.use("/note", authenticator, NoteRoutes);
app.use("/task", authenticator, TaskRoutes);

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
