const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const app = express();

// Ensure that your React app's origin is allowed
app.use(cors({
  origin: 'http://localhost:3000', // React app URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Allows cookies/auth headers to be sent
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL connection setup
const db = mysql.createConnection({
  host: "127.0.0.1", // Server host
  user: "root", // MySQL username
  password: "root", // MySQL password (adjust as needed)
  database: "users", // Database name
  port: 3309, // Port for phpMyAdmin MariaDB connection
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log("MySQL Connected");
});
// Register Route
app.post("/register", (req, res) => {
  console.log(req.body);
  const { name, email, tel, password, confirmPass } = req.body;

  if (password !== confirmPass) {
    return res.status(400).send("Passwords do not match");
  }

  // Hash password before saving it
  const hashedPassword = bcrypt.hashSync(password, 10);

  const sql = "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)";

  db.query(sql, [name, email, tel, hashedPassword], (err, result) => {
    if (err) {
      console.error(err);
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).send("User already exists");
      }
      return res.status(500).send("Error registering user");
    }
    res.status(201).send("User registered...");
  });
});

// Login Route
app.post("/login", (req, res) => {
  const { email, pass } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) return res.status(500).send("Database error");
    if (results.length === 0) return res.status(400).send("Invalid email or password");

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(pass, user.password);

    if (!isPasswordValid) return res.status(400).send("Invalid email or password");

    const token = jwt.sign({ id: user.id }, "secretKey", { expiresIn: "1h" });
    res.send({ message: "Login successful", token });
  });
});
// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Bearer token
  if (!token) {
      return res.status(403).send("Access denied");
  }
  try {
      const verified = jwt.verify(token, "secretKey"); // Verify token with secret
      req.user = verified; // Set the user ID in the request
      next();
  } catch (error) {
      return res.status(401).send("Invalid token");
  }
};
// Profile route
app.get("/profile", verifyToken, (req, res) => {
  const userId = req.user.id;

  const sql = "SELECT name, email, phone FROM users WHERE id = ?";
  db.query(sql, [userId], (err, result) => {
      if (err) return res.status(500).send("Database error");
      if (result.length === 0) return res.status(404).send("User not found");

      res.json(result[0]); // Send the user details
  });
});
// Send OTP to the user's email
let otpStorage = {}; // In-memory OTP storage, use Redis/DB for production

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'srinivaskatreedi369@gmail.com', // Your email
    pass: 'hypm wspq pwim jwdp', // Your app-specific password
  },
});

// Send OTP Route
app.post("/send-otp", (req, res) => {
  const { email } = req.body;
  console.log('Received email for OTP:', email); // Log received email

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Database error");
    }
    if (results.length === 0) {
      console.log('User not found for email:', email); // Log if user is not found
      return res.status(404).send("User not found");
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStorage[email] = otp;

    // Send email with OTP
    const mailOptions = {
      from: "srinivaskatreedi369@gmail.com",
      to: email,
      subject: "Your Password Reset OTP",
      text: `Your OTP for password reset is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).send("Error sending email");
      }
      res.send("OTP sent to your email");
    });
  });
});

// Verify OTP Route
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  // Check if OTP matches the one sent to the user's email
  if (!otpStorage[email] || otpStorage[email] !== otp) {
    return res.status(400).send("Invalid OTP");
  }

  // If OTP matches, send success message
  res.send("OTP verified");
});

// Reset password route
app.post("/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!otpStorage[email] || otpStorage[email] !== otp) {
    return res.status(400).send("Invalid OTP");
  }

  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  const sql = "UPDATE users SET password = ? WHERE email = ?";

  db.query(sql, [hashedPassword, email], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Error updating password");
    }
    delete otpStorage[email]; // Clear OTP after successful reset
    res.send("Password has been reset");
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.post('/login', async (req, res) => {
  const { email, pass } = req.body;

  // Check if the user exists and password matches
  const user = await db.query('SELECT * FROM users WHERE email = ?', [email]);

  if (user && bcrypt.compareSync(pass, user.password)) {
    const token = jwt.sign({ id: user.id }, 'your-secret-key', { expiresIn: '1h' });
    return res.json({ message: 'Login successful', token });
  }

  res.status(401).json({ message: 'Invalid credentials' });
});
