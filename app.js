const express = require("express");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv").config();
const jwt = require("jsonwebtoken");
const users = require("./users");
const cors = require("cors");

app = express();
app.use(express.json());
app.use(
  cors({
    // origin: "http://localhost:3000",
    origin: "*",
    credentials: true,
  })
);

// users = [];

// jwt auth middleware
function authTokenMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); //invalid token
    }
    req.user = user;
    next();
  });
}

const PORT = 4000;
// const JWT_SECRET = process.env.JWT_SECRET;
const JWT_SECRET = "209rfioeforeoijnrifv9rejerjfouew09juf09we";

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const existinguser = users.find((u) => u.username === username);
  if (existinguser) {
    return res.status(400).json({ messag: "user exist already" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "user registered" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "invalid credentials" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "invalid credentials" });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// protected route
app.get("/profile", authTokenMiddleware, (req, res) => {
  res.json({ message: `welcome, ${req.user.username}` });
});

app.listen(PORT, () => {
  console.log("server started");
});
