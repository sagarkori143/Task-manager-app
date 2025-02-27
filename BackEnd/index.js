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

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
const allowedOrigins = [
  "https://task-manager-app-three-pi.vercel.app",
  "http://localhost:3000"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// Session Configuration
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URL,
  collectionName: "sessions",
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: true,
      maxAge: 1000 * 60 * 60 * 24,
      sameSite: 'none'
    },
  })
);

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get("/", (req, res) => {
  res.json({ message: "Server is running" });
});

app.get("/getUser", (req, res, next) => {
  if (req.user) {
    return res.json(req.user); // Respond with the user data if authenticated
  } else {
    return res.status(401).json({ error: "Unauthorized" }); // Handle unauthenticated users
  }
});


// Registration
app.post("/register", async (req, res) => {
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

// Authentication Routes
app.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

// OAuth Callbacks
const oauthCallback = (strategy) => (req, res) => {
  const successRedirect = `${process.env.FRONTEND_DOMAIN}/Home`;
  const failureRedirect = `${process.env.FRONTEND_DOMAIN}/login`;
  passport.authenticate(strategy, {
    successRedirect,
    failureRedirect
  })(req, res);
};

app.get("/google/callback", oauthCallback("google"));
app.get("/facebook/callback", oauthCallback("facebook"));

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // This will create the session and set the cookie automatically
    req.login(user, (err) => {
      if (err) return next(err);

      // Session cookie is automatically set on successful login
      console.log("Session Cookie Set:", req.sessionID); 
      return res.status(200).json({
        success: true,
        message: "Successfully logged in",
        user,
      });
    });
  })(req, res, next);
});


// Logout
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    req.session.destroy((err) => {
      if (err) return res.status(500).json({ error: "Session destruction failed" });
      res.clearCookie('connect.sid');
      res.json({ message: "Successfully logged out" });
    });
  });
});

// Password Reset
app.post("/forgotpass", async (req, res) => {
  // ... (keep existing implementation)
});

app.post("/resetPassword/:id/:token", async (req, res) => {
  // ... (keep existing implementation)
});


// Authentication Middleware
const authenticator = (req, res, next) => {
  console.log("this is the request coming from client",req)
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: "Unauthorized" });
};

// Protected Routes
app.use("/todo", authenticator, TodoRoutes);
app.use("/note", authenticator, NoteRoutes);
app.use("/task", authenticator, TaskRoutes);

// Server Start
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;