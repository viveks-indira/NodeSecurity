const fs = require("fs");
const https = require("https");
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession=require('cookie-session')
require("dotenv").config();

const PORT = 3000;
const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1:process.env.SECRET_KEY_1,
  COOKIE_KEY_2:process.env.SECRET_KEY_2,
};

const Auth_Options = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("profile", profile,"Access token ", accessToken ,"Refresh token " ,refreshToken);
  done(null, profile);
}

passport.use(new Strategy(Auth_Options, verifyCallback));
passport.serializeUser((user,done)=>{
  done(null,user.id);
});
passport.deserializeUser((obj,done)=>{
  done(null,obj)
});

const app = express();

app.use(helmet());

app.use(cookieSession({
  name:'session',
  maxAge: 24 * 60 * 60 *1000,
  keys:[config.COOKIE_KEY_1,config.COOKIE_KEY_2]
}))
app.use(passport.initialize());
app.use(passport.session());

function checkPoint(req, res, next) {
  console.log("Current user :", req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({ error: "you must login" });
  }
  next();
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
     scope:['email'],
  })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("google called backs !");
  }
);
app.get("/failure", (req, res) => {
  return res.send("Failed to log in !");
});

app.get("/auth/logout", (req, res) => {
  req.logout();
  return res.redirect('/');
});

app.get("/secret", checkPoint, (req, res) => {
  res.send("your secret value ");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listning ${PORT}`);
  });
