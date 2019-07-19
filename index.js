const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const randtoken = require('rand-token');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cors = require('cors');
const express = require('express');
const app = express();

const refreshTokens = {};
const SECRET = 'VERY_SECRET_KEY!';
const passportOpts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: SECRET
};

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

passport.use(new JwtStrategy(passportOpts, function (jwtPayload, done) {
  const expirationDate = new Date(jwtPayload.exp * 1000);
  if (expirationDate < new Date()) {
    return done(null, false);
  }
  done(null, jwtPayload);
}))

passport.serializeUser(function (user, done) {
  done(null, user.username)
});

app.post('/login', function (req, res) {
  const { username, password } = req.body;
  const user = {
    'username': username,
    'role': 'admin'
  };
  const token = jwt.sign(user, SECRET, { expiresIn: 600 })
  const refreshToken = randtoken.uid(256);
  refreshTokens[refreshToken] = username;
  res.json({ jwt: token, refreshToken: refreshToken });
});

app.post('/logout', function (req, res) {
  const refreshToken = req.body.refreshToken;
  if (refreshToken in refreshTokens) {
    delete refreshTokens[refreshToken];
  }
  res.sendStatus(204);
});

app.post('/refresh', function (req, res) {
  const refreshToken = req.body.refreshToken;


  if (refreshToken in refreshTokens) {
    const user = {
      'username': refreshTokens[refreshToken],
      'role': 'admin'
    }
    const token = jwt.sign(user, SECRET, { expiresIn: 600 });
    res.json({ jwt: token })
  }
  else {
    res.sendStatus(401);
  }
});

app.get('/auth', function (req, res) {
  try {
    jwt.verify(req.headers.authorization.replace('Bearer ', ''), SECRET);
    res.json('authorized');
  }
  catch (error) {
    console.log(error);
    if (error.message == "invalid signature" ||error.message ==  "jwt malformed") {
      res.sendStatus(403);
    } else if (error.message = "jwt expired") {
      res.sendStatus(401);
    }
  }
})

app.listen(8080);
