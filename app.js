//jshint esversion:6
require("dotenv").config()
const encrypt = require("bcryptjs");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.urlencoded());
app.use(express.static("public"));
app.set("view engine","ejs");

app.use(session({
  secret: "navi",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secretsDB", {useNewUrlParser: true,useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

const secretSchema = new mongoose.Schema({
  email: String,
  password: String,
  username: String,
  secrets: Array
});

secretSchema.plugin(passportLocalMongoose);
secretSchema.plugin(findOrCreate);

const User = mongoose.model("user",secretSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request,accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ username: profile.id, email: profile.email }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'profile','email' ] }
));

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/secrets",function(req,res){
  if(req.isAuthenticated()){
    User.find({'secrets': {$ne:null}},function(err,results){
      console.log(results);
      if(err){
        console.log(err);
      }
      else{
        if(results){
          res.render("secrets",{allUserSecrets:results});
        }
      }
    });
  }else{
    res.redirect("/login");
  }
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const userSecret = req.body.secret;
  User.findById(req.user.id,function(err,found){
    if (err){
      console.log(err);
    }
    else{
      if(found){
        found.secrets.push(userSecret);
        found.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/register",function(req,res){
User.register({username:req.body.username},req.body.password,function(err,user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
});
});

app.post("/login",function(req,res){
  const user = new User({
    username: req.body.username,
    password:req.body.password
  });
   req.login(user,function(err){
     if(err){
       console.log(err);
       res.redirect("/login");
     }else{
       passport.authenticate("local")(req,res,function(){
         res.redirect("/secrets");
     });
   }
   });
});

app.listen(3000,function(){
  console.log("server is running on port 3000");
});
