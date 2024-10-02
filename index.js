const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/edify', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB");
}).catch((err) => {
    console.error("Error connecting to MongoDB:", err);
});

// Define User schema and model
const User = mongoose.model('User', {
    username: String,
    empid: String,
    email: String,
    password: String, // Hashed password
    role: String,
    verify: String
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', [
    path.join(__dirname, 'user', 'views'),
    path.join(__dirname, 'admin', 'views'),
    path.join(__dirname, 'superadmin', 'views')
]);
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Routes
app.get('/', function (req, res) {
    res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/login', function (req, res) {
    res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/signup', function (req, res) {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// Login route
app.post('/login', async (req, res) => {
    const { empid, password } = req.body;

    try {
        const user = await User.findOne({ empid });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.sendFile(path.join(__dirname, 'login1.html'));
        }

        req.session.user = user;

        switch (user.verify) {
            case "1":
                res.redirect('/user');
                break;
            case "2":
                res.redirect('/admin');
                break;
            case "3":
                res.redirect('/superadmin');
                break;
            default:
                res.sendFile(path.join(__dirname, 'login1.html'));
        }
    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Signup route
app.post('/signup', async (req, res) => {
    const { username, empid, email, password, role, verify } = req.body;

    try {
        const existingUser = await User.findOne({ empid });
        if (existingUser) {
            return res.send('Employee ID already exists');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({ username, empid, email, password: hashedPassword, role, verify });
        res.sendFile(path.join(__dirname, 'login.html'));
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).send('Internal Server Error');
    }
});

// User route
app.get('/user', authorizeUser, (req, res) => {
    const username = req.session.user.username;
    res.render('userportal', { username: username });
});

const userRoutes = require('./user/routes/user');
app.use('/user', authorizeUser, userRoutes);

// Admin route
const adminRoutes = require('./admin/routes/admin');
app.use('/admin', authorizeAdmin, adminRoutes);

// Superadmin route
const superadminRoutes = require('./superadmin/routes/superadmin');
app.use('/superadmin', authorizeSuperadmin, superadminRoutes);

// Authorization middleware for user route
function authorizeUser(req, res, next) {
    if (req.session.user && req.session.user.verify === "1") {
        next(); // User is authorized, continue to the next middleware or route handler
    } else {
        res.status(403).send('Unauthorized'); // User is not authorized
    }
}

// Authorization middleware for admin route
function authorizeAdmin(req, res, next) {
    if (req.session.user && req.session.user.verify === "2") {
        next(); // Admin is authorized, continue to the next middleware or route handler
    } else {
        res.status(403).send('Unauthorized'); // Admin is not authorized
    }
}

// Authorization middleware for superadmin route
function authorizeSuperadmin(req, res, next) {
    if (req.session.user && req.session.user.verify === "3") {
        next(); // Superadmin is authorized, continue to the next middleware or route handler
    } else {
        res.status(403).send('Unauthorized'); // Superadmin is not authorized
    }
}

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/'); // Redirect to the login page
    });
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
