const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const dotenv = require('dotenv').config();
const bodyParser = require('body-parser');

const connectDb = require('./config/dbConnection');
const User = require('./models/userModel');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors({
    origin: 'http://localhost:5173', // Your React app's URL
    credentials: true // Allow cookies to be sent
}));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
    secret: 'ytytuyuygjhgjgjh676876hkjh', // Replace with a strong secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true, // Prevents client-side JS from accessing cookies
        maxAge: 1000 * 60 * 60 * 1 // Session expiry: 1 hour
    }
}));


connectDb();

// const users = [
//     {
//         id: 1,
//         username: 'john_doe',
//         password: '$2a$10$wVzY8ZDhHsCdcQcA4LPKieXUGWt/Lh9cgFXjig6MG9G.6cHsxXlF2' // Hash for "password123"
//     }
// ];


// Route: User Login

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(req.body);

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        console.log('user is : ', user);

        const isMatch = await bcrypt.compare(password, user.password);

        console.log(isMatch);

        if (!isMatch) {
            console.log("hellooo");
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Save user info in session
        req.session.user = { id: user.id, username: user.username };

        // Set a cookie for 24 hours with user ID
        res.cookie('userId', user.id, {
            maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
            httpOnly: true, // Makes the cookie inaccessible to client-side JavaScript
            secure: false,  // Set to 'true' if using HTTPS
            sameSite: 'lax', // Helps prevent CSRF attacks
        });

        res.json({ message: 'Login successful', user: { username: user.username } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});


// Route: Check Session
app.get('/session', (req, res) => {
    if (req.session.user) {
        res.json({ message: 'Session active', user: req.session.user });
    } else {
        res.status(401).json({ message: 'Not logged in' });
    }
});


app.get('/api/check-auth', (req, res) => {
    const userId = req.cookies.userId;

    console.log("user id is : ", userId);

    if (userId) {
        return res.json({ isAuthenticated: true, userId });
    }
    console.log("user is not authenticated");

    res.json({ isAuthenticated: false });
});
  


app.post('/api/signup', async (req, res) => {
    try {
      const { username, email ,password } = req.body;
  
      // Check for missing fields
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required." });
      }
  
      // Check if the user already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: "Username already exists." });
      }
  
      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
  
      // Save new user to the database
      const newUser = new User({
        username,
        email: email,
        password: hashedPassword,
      });
  
      await newUser.save();
      res.status(201).json({ message: "User created successfully!" });
    } catch (error) {
      console.error("Signup error:", error);
      res.status(500).json({ error: "Server error. Please try again later." });
    }
  });

// Route: User Logout
app.post('/api/logout', (req, res) => {
    try {
        // Destroy the session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ message: 'Logout failed' });
            }

            // Clear the userId cookie
            res.clearCookie('userId'); // Name of the cookie set during login

            console.log('Session destroyed and cookie cleared');
            res.status(200).json({ message: 'Logout successful' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during logout' });
    }
});

  

// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
