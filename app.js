const express = require('express');
const bodyParser = require('body-parser');
const path = require('path'); 
const bcrypt = require('bcryptjs');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));



// MongoDB connection
mongoose.connect("mongodb://localhost:27017/secrets", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Express session
app.use(
  session({
    secret: "mySecretKey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: "mongodb://localhost:27017/secrets" }),
  })
);

// Schema and Model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  secrets: [String], // Array to store user secrets
});

const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => res.render("home"));

app.get("/register", (req, res) => res.render("register", { message: undefined }));

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
      return res.render("register", { message: "Email already registered. Please login." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email: username, password: hashedPassword });
    await newUser.save();

    req.session.userId = newUser._id;
    res.redirect("/secrets");
  } catch (err) {
    console.error("Registration error:", err);
    res.render("register", { message: "An error occurred during registration." });
  }
});

app.get("/login", (req, res) => res.render("login", { message: undefined }));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const foundUser = await User.findOne({ email: username });
    if (!foundUser) {
      return res.render("login", { message: "User not found. Please register first." });
    }

    const isMatch = await bcrypt.compare(password, foundUser.password);
    if (isMatch) {
      req.session.userId = foundUser._id;
      res.redirect("/secrets");
    } else {
      res.render("login", { message: "Incorrect password. Please try again." });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { message: "An error occurred during login." });
  }
});

/*app.post('/login', (req, res) => {
    // Dummy login flow
    const { username, password } = req.body;
    // Authenticate here (mock for now)
    if (username === 'test' && password === 'password') {
        res.redirect('/secrets'); // Redirect to secrets page upon successful login
    } else {
        res.render('login', { message: 'Invalid credentials. Please try again.' });
    }
});*/

app.get("/secrets", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");

  try {
    const user = await User.findById(req.session.userId);
    res.render("secrets", { secrets: user.secrets });
  } catch (err) {
    console.error("Error fetching secrets:", err);
    res.redirect("/login");
  }
});

/*app.post("/submit", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");

  try {
    const { secret } = req.body;
    const user = await User.findById(req.session.userId);
    user.secrets.push(secret);
    await user.save();

    res.redirect("/secrets");
  } catch (err) {
    console.error("Error submitting secret:", err);
    res.redirect("/login");
  }
});*/

app.post('/submit', (req, res) => {
    const secret = req.body.secret;
    console.log(`New secret: ${secret}`);
    res.redirect('/secrets'); // Redirect back to the secrets page
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Logout error:", err);
    res.redirect("/");
  });
});

app.listen(5021, () => console.log("Server Started on port 5021"));
