const express = require("express");
const expSession = require("express-session");
const app = express();
const mongoose = require("mongoose");
const passport = require("passport");
const bodyParser = require("body-parser");
const LocalStrategy = require("passport-local");
const mongoSanitize = require("express-mongo-sanitize");
const rateLimit = require("express-rate-limit");
const xss = require("xss-clean");
const helmet = require("helmet");
const User = require("./models/user");

// Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

// =======================
//   APP MIDDLEWARE
// =======================
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Preventing DOS Attacks - Body Parser 
app.use(express.json({ limit: "10kb" }));

// =======================
//   SESSION + PASSPORT
// =======================
app.use(
  expSession({
    secret: "mysecret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: false, // local dev (HTTP)
      maxAge: 1 * 60 * 1000 // 10 minutes
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
passport.use(new LocalStrategy(User.authenticate()));

// =======================
//      O W A S P
// =======================

// Data Sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());

// Data Sanitization against XSS attacks
app.use(xss());

// Helmet to secure connection and data
app.use(helmet());

// Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000, // 1 hour
  message: "Too many requests"
});

// app.use('/routeName', limit);// Setting limiter on specific route

// Apply limiter on specific routes (login/register)
app.use("/login", limit);
app.use("/register", limit);

// =======================
//      R O U T E S
// =======================
app.get("/", (req, res) => res.render("home"));

app.get("/userprofile", (req, res) => res.render("userprofile"));

// LOGIN
app.get("/login", (req, res) => res.render("login"));

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/userprofile",
    failureRedirect: "/login"
  })
);

// REGISTER (GET)
app.get("/register", (req, res) => {
  res.render("register", { errors: null, formData: {} });
});

// REGISTER (POST)
app.post("/register", async (req, res) => {
  const { username, password, email, phone } = req.body;
  let errors = {};

  // Username validation (min 3 chars)
  if (!username || username.length < 3) {
    errors.username = "Username must be at least 3 characters";
  }

  // Password validation (min 8 + uppercase + lowercase + number)
  if (!password || password.length < 8) {
    errors.password = "Password must be at least 8 characters";
  } else {
    if (!/[A-Z]/.test(password)) errors.password = "Password must include at least 1 uppercase letter";
    if (!/[a-z]/.test(password)) errors.password = "Password must include at least 1 lowercase letter";
    if (!/[0-9]/.test(password)) errors.password = "Password must include at least 1 number";
  }

  if (Object.keys(errors).length > 0) {
    return res.render("register", {
      errors,
      formData: { username, email, phone }
    });
  }

  try {
    await User.register(new User({ username, email, phone }), password);
    return res.redirect("/login");
  } catch (err) {
    errors.general = err.message;
    return res.render("register", {
      errors,
      formData: { username, email, phone }
    });
  }
});

// LOGOUT
app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

// SERVER
app.listen(process.env.PORT || 3000, (err) => {
  if (err) console.log(err);
  else console.log("Server Started At Port 3000");
});