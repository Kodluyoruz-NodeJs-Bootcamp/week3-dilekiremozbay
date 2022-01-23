import "dotenv/config";
import path from "path";
import bodyParser from "body-parser";
import MongoStore from "connect-mongo";
import { Request, Response } from "express";
import express from "express";
import session from "express-session";
import expressLayouts from "express-ejs-layouts";
import mongoose from "mongoose";
import authController from "./controllers/auth";
import authRoutes from "./routes/auth";

import { client } from "./session/client";
import bearerToken from "express-bearer-token";

const app = express();
const port = process.env.PORT;

Promise.all([
  client.connect(),
  mongoose.connect(
    `${process.env.DB_PROTOCOL}://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}/${process.env.DB_NAME}?${process.env.DB_PARAMS}`
  ),
])
  .then(() => {
    console.log("Connected to MongoDB");

    setupRoutes(app);

    app.listen(port, () => {
      console.log("API Listening to http://localhost:" + port);
    });
  })
  .catch((err) => {
    console.log("mongose connection failed", err);
  });

process.on("SIGINT", () => {
  mongoose.connection.close(() => {
    console.log("Mongoose disconnected on app termination");
    process.exit(0);
  });
});

function setupRoutes(app: express.Application) {
  app.use(bearerToken());
  app.use(express.static("public"));
  app.use(expressLayouts);
  app.set("layout", "./layout");
  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "./views"));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));

  app.use(
    session({
      secret: "supersecret difficult to guess string",
      cookie: {},
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({ client: client }),
    })
  );

  app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
      res.redirect("/");
    });
  });

  //Declare API category endpoints
  app.use("/", authRoutes);

  //login sayfasını render edildi
  app.get("/login", (req, res) => {
    res.render("login", { title: "About Page" });
  });

  //login sayfasını render edildi
  app.get("/register", (req, res) => {
    res.render("register", { title: "About Page" });
  });

  app.use(errorHandler as any);

  function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: express.NextFunction
  ) {
    if (err.name === "UnauthorizedError") {
      return res.status(401).send({
        message: "Invalid token",
      });
    }

    return res.status(500).send({
      statusCode: 500,
      message: err.message,
    });
  }
}
