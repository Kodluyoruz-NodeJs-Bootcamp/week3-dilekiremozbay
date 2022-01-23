// node_modules/tsup/assets/esm_shims.js
import { fileURLToPath } from "url";
import path from "path";
var getFilename = () => fileURLToPath(import.meta.url);
var getDirname = () => path.dirname(getFilename());
var __dirname = /* @__PURE__ */ getDirname();

// src/app.ts
import "dotenv/config";
import path2 from "path";
import bodyParser from "body-parser";
import MongoStore from "connect-mongo";
import express2 from "express";
import session from "express-session";
import expressLayouts from "express-ejs-layouts";
import mongoose2 from "mongoose";

// src/routes/auth.ts
import express from "express";

// src/models/User.ts
import mongoose from "mongoose";
var userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    min: 3,
    max: 25
  },
  lastName: {
    type: String,
    required: true,
    min: 3,
    max: 25
  },
  username: {
    type: String,
    required: true,
    min: 4,
    max: 25
  },
  password: {
    type: String,
    required: true,
    min: 6,
    max: 255
  },
  security: {
    tokens: [
      {
        _id: String,
        refreshToken: String,
        createdAt: Date
      }
    ]
  }
});
var UserModel = mongoose.model("User", userSchema);

// src/controllers/auth.ts
import jwt from "jsonwebtoken";

// src/helpers/validation.ts
import Joi from "joi";
var registerSchema = Joi.object({
  username: Joi.string().min(4).max(25),
  password: Joi.string().min(6).max(255),
  firstName: Joi.string().min(3).max(25),
  lastName: Joi.string().min(3).max(25)
});
var loginSchema = Joi.object({
  username: Joi.string().min(4).max(25),
  password: Joi.string().min(6).max(255)
});
var validation_default = { registerSchema, loginSchema };

// src/controllers/auth.ts
import bcrypt from "bcrypt";
import _ from "lodash";
var login = async (req, res) => {
  const { error } = validation_default.loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      status: 400,
      message: "INPUT_ERRORS",
      errors: error.details,
      original: error._original
    });
  }
  const user = await UserModel.findOne({ username: req.body.username });
  if (!user) {
    return res.status(401).json({ message: "incorrect username or password" });
  }
  const validatePassword = await bcrypt.compare(req.body.password, user.password);
  if (!validatePassword) {
    return res.status(401).json({ message: "incorrect username or password" });
  }
  const browserDetails = { userAgent: req.headers["user-agent"] };
  const accessToken = jwt.sign({
    _id: user.id,
    browserDetails
  }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
  const refreshToken = jwt.sign({
    _id: user.id
  }, process.env.SECRET_REFRESH_TOKEN, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
  await addRefreshToken(user, refreshToken);
  req.session.browserDetails = browserDetails;
  res.redirect("/users");
};
var register = async (req, res) => {
  const { error } = validation_default.registerSchema.validate(req.body, {
    abortEarly: false
  });
  if (error) {
    return res.status(400).json({
      status: 400,
      message: "INPUT_ERRORS",
      errors: error.details,
      original: error._original
    });
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);
  const user = new UserModel({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    username: req.body.username,
    password: hashedPassword,
    security: {
      tokens: []
    }
  });
  await user.save();
  const accessToken = jwt.sign({
    _id: user.id,
    username: user.username
  }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
  const refreshToken = jwt.sign({
    _id: user.id,
    username: user.username
  }, process.env.SECRET_REFRESH_TOKEN, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
  await UserModel.updateOne({ username: user.username }, {
    $push: {
      "security.tokens": {
        refreshToken,
        createdAt: new Date()
      }
    }
  });
  res.redirect("/login");
};
var token = async (req, res) => {
  const refreshToken = req.body.refreshToken;
  const decodeRefreshToken = jwt.verify(refreshToken, process.env.SECRET_REFRESH_TOKEN);
  const user = await UserModel.findOne({
    username: decodeRefreshToken.sub
  });
  if (!user) {
    return res.status(401).json({ message: "Account deleted" });
  }
  const existingRefreshTokens = user.security.tokens;
  const refreshTokenExists = existingRefreshTokens.some((token2) => token2.refreshToken === refreshToken);
  if (!refreshTokenExists) {
    return res.status(401).json({ error: { status: 401, message: "INVALID_REFRESH_TOKEN" } });
  }
  const accessToken = jwt.sign({
    _id: user.id
  }, process.env.SECRET_ACCESS_TOKEN, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
  res.status(200).json({
    success: {
      status: 200,
      message: "ACCESS_TOKEN_GENERATED",
      accessToken
    }
  });
};
var addRefreshToken = async (user, refreshToken) => {
  const existingRefreshTokens = user.security.tokens;
  if (existingRefreshTokens.length < 5) {
    await UserModel.updateOne({ username: user.username }, {
      $push: {
        "security.tokens": {
          refreshToken,
          createdAt: new Date()
        }
      }
    });
  } else {
    await UserModel.updateOne({ username: user.username }, {
      $pull: {
        "security.tokens": {
          _id: existingRefreshTokens[0]._id
        }
      }
    });
    await UserModel.updateOne({ username: user.username }, {
      $push: {
        "security.tokens": {
          refreshToken,
          createdAt: new Date()
        }
      }
    });
  }
};
function authorizer(req, res, next) {
  console.log("authorization token", req.token);
  jwt.verify(req.token, process.env.SECRET_ACCESS_TOKEN, cb);
  function cb(err, decoded) {
    var _a;
    console.log("verify result", { err, decoded, session: req.session });
    if (err) {
      return res.status(401).json({ message: err.message });
    }
    if (((_a = req.session.browserDetails) == null ? void 0 : _a.userAgent) !== decoded.browserDetails.userAgent) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.tokenData = decoded;
    next();
  }
}
async function me(req, res) {
  const user = await UserModel.findOne({ _id: req.tokenData._id });
  console.log("req.token", req.token);
  if (!user) {
    return res.status(401).json({ message: "Account deleted" });
  }
  res.json(cleanUserObject(user));
}
async function findAllUsers(req, res) {
  const users = await UserModel.find({});
  const cleanedUsers = users.map(cleanUserObject);
  res.json(cleanedUsers);
}
function cleanUserObject(user) {
  return _.pick(user, ["_id", "username", "firstName", "lastName"]);
}
var auth_default = { login, register, token, me, authorizer, findAllUsers };

// src/routes/auth.ts
var router = express.Router();
router.post("/login", auth_default.login);
router.post("/register", auth_default.register);
router.post("/token", auth_default.token);
router.get("/me", auth_default.authorizer, auth_default.me);
router.get("/users", auth_default.findAllUsers);
var auth_default2 = router;

// src/session/client.ts
import "dotenv/config";
import { MongoClient } from "mongodb";
var mongoURL = buildMongoURL(process.env);
var client = new MongoClient(mongoURL);
function buildMongoURL(env) {
  const creds = buildUserCredentials(env);
  const dbProtocol = env.DB_PROTOCOL || "mongodb";
  const srvFeatureEnabled = dbProtocol === "mongodb+srv";
  const dbPort = srvFeatureEnabled ? "" : `:${env.DB_PORT}`;
  const dbAddr = `${env.DB_HOST}${dbPort}`;
  const dbName = env.DB_NAME;
  const dbParams = buildDBParamsString(env);
  return `${dbProtocol}://${creds}${dbAddr}/${dbName}${dbParams}`;
}
function buildUserCredentials(env) {
  const user = env.DB_USER;
  const pass = env.DB_PASS;
  if (user && pass) {
    return `${user}:${pass}@`;
  } else if (user) {
    return `${user}@`;
  } else if (pass) {
    throw new Error("Password provided without username");
  }
  return "";
}
function buildDBParamsString(env) {
  const params = env.DB_PARAMS;
  if (params) {
    return `?${params}`;
  }
  return "";
}

// src/app.ts
import bearerToken from "express-bearer-token";
var app = express2();
var port = process.env.PORT;
Promise.all([
  client.connect(),
  mongoose2.connect(`${process.env.DB_PROTOCOL}://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}/${process.env.DB_NAME}?${process.env.DB_PARAMS}`)
]).then(() => {
  console.log("Connected to MongoDB");
  setupRoutes(app);
  app.listen(port, () => {
    console.log("API Listening to http://localhost:" + port);
  });
}).catch((err) => {
  console.log("mongose connection failed", err);
});
process.on("SIGINT", () => {
  mongoose2.connection.close(() => {
    console.log("Mongoose disconnected on app termination");
    process.exit(0);
  });
});
function setupRoutes(app2) {
  app2.use(bearerToken());
  app2.use(express2.static("public"));
  app2.use(expressLayouts);
  app2.set("layout", "./layout");
  app2.set("view engine", "ejs");
  app2.set("views", path2.join(__dirname, "./views"));
  app2.use(bodyParser.json());
  app2.use(bodyParser.urlencoded({ extended: true }));
  app2.use(session({
    secret: "supersecret difficult to guess string",
    cookie: {},
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ client })
  }));
  app2.post("/logout", (req, res) => {
    req.session.destroy((err) => {
      res.redirect("/");
    });
  });
  app2.use("/", auth_default2);
  app2.get("/login", (req, res) => {
    res.render("login", { title: "About Page" });
  });
  app2.get("/register", (req, res) => {
    res.render("register", { title: "About Page" });
  });
  app2.use(errorHandler);
  function errorHandler(err, req, res, next) {
    if (err.name === "UnauthorizedError") {
      return res.status(401).send({
        message: "Invalid token"
      });
    }
    return res.status(500).send({
      statusCode: 500,
      message: err.message
    });
  }
}
//# sourceMappingURL=app.mjs.map