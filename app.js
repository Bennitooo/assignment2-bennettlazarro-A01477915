require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();
const Joi = require("joi");
const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

// Session middleware
app.use(
  session({
    secret: node_session_secret, // Change this to a secure secret in production
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
  }),
);

app.use(express.static("public"));

app.post("/nosql-injection", async (req, res) => {
  var name = req.body.user;

  if (!name) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`,
    );
    return;
  }
  console.log("user: ", name);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>",
    );
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${name}</h1>`);
});

// Routes

app.get("/", (req, res) => {
  if (req.session.authenticated) {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <form action="/members" method="get">
        <button>Go to Members Area</button>
      </form>
      <form action="/logout" method="get">
        <button>Logout</button>
      </form>
    `);
  } else {
    res.send(`
      <form action="/signup" method="get">
        <button>Sign Up</button>
      </form>
      <form action="/login" method="get">
        <button>Log In</button>
      </form>
    `);
  }
});

app.get("/signup", (req, res) => {
  var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <br>
    <input name='email' type='email' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
  `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var password = req.body.password;
  var email = req.body.email;

  if (!name) {
    res.send(`Name is required. <a href="/signup">Try again</a>`);
    return;
  }
  if (!email) {
    res.send(`Email is required. <a href="/signup">Try again</a>`);
    return;
  }
  if (!password) {
    res.send(`Password is required. <a href="/signup">Try again</a>`);
    return;
  }

  const schema = Joi.object({
    name: Joi.string().alphanum().max(20).required(),
    email: Joi.string().max(50).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(`Invalid input. <a href="/signup">Try again</a>`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(30).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    res.send(`Invalid email. <a href="/login">Try again</a>`);
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    res.send(`Email not found. <a href="/login">Try again</a>`);
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
    return;
  } else {
    res.send(
      `Invalid email/password combination. <a href="/login">Try again</a>`,
    );
    return;
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  const images = ["patrick1.png", "patrick2.png", "patrick3.png"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.name}.</h1>
    <img src='/${randomImage}' style='width:300px;'>
    <br><br>
    <form action="/logout" method="get">
      <button>Sign out</button>
    </form>
  `);
});

// 404 handler
app.use((req, res) => {
  res.status(404).send(`<h1>Page not found - 404</h1>`);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;
