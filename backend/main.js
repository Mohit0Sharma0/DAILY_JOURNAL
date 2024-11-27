const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const cookieParser = require('cookie-parser');
app.use(cookieParser());

// CORS setup for frontend connection
const cors = require('cors');
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));



// Connect to MongoDB Atlas
mongoose.connect('mongodb+srv://amitsinghbharangar001:amitsingh@dailyjournal.ztlj9.mongodb.net/?retryWrites=true&w=majority&appName=DailyJournal')
    .catch(err => console.error('MongoDB Atlas connection error:', err));

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true }, // Change 'name' to 'username'
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Entry schema and model
const entrySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    content: String,
    date: {
        type: String,
        default: () => {
            const now = new Date();
            return now.toISOString().split('T')[0]; // Format as YYYY-MM-DD
        },
    },
});

const Entry = mongoose.model('Entry', entrySchema);

// Middleware for authenticating JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from cookies
    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    jwt.verify(token, 'secretKey', (err, decoded) => {
        if (err) {
            return res.status(403).send('Invalid token.');
        }
        req.user = decoded;
        next();
    });
};


// User registration endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send('User already exists.');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).send('User registered successfully.');
    } catch (error) {
        res.status(500).send('Error registering user: ' + error.message);
    }
});

// User login endpoint
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send('Invalid email or password.');
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).send('Invalid email or password.');
        }

        const token = jwt.sign({ userId: user._id }, 'secretKey', { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send('Error logging in: ' + error.message);
    }
});

// Create a new task
app.post('/createEntry', authenticateJWT, async (req, res) => {
    try {
        const { title, content } = req.body;
        const entry = new Entry({ userId: req.user.userId, title, content });
        await entry.save();

        // Return JSON response
        res.status(201).json({ message: 'Entry created successfully.' });
    } catch (error) {
        // Return JSON response for error
        res.status(500).json({ message: 'Error creating Entry: ' + error.message });
    }
});

// Read tasks
app.get('/entries', authenticateJWT, async (req, res) => {
    try {
        // Fetch the entries from the database for the logged-in user
        const entries = await Entry.find({ userId: req.user.userId });

        res.json(entries);  // Send the entries as a response
    } catch (error) {
        console.error(error); // Log error to console for debugging
        res.status(500).json({ message: 'Error fetching entries: ' + error.message });
    }
});

app.get('/entries/:id', authenticateJWT, async (req, res) => {
    try {
        const entry = await Entry.findById(req.params.id);

        if (!entry) {
            return res.status(404).json({ message: 'Entry not found' });
        }

        if (entry.userId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'You are not authorized to view this entry' });
        }

        res.json(entry);  // Send the entry as a response
    } catch (error) {
        console.error(error); // Log error for debugging
        res.status(500).json({ message: 'Error fetching entry: ' + error.message });
    }
});

// Update a task
app.put('/tasks/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, completed } = req.body;

        const task = await Task.findOneAndUpdate(
            { _id: id, userId: req.user.userId },
            { title, description, completed },
            { new: true }
        );

        if (!task) {
            return res.status(404).send('Task not found.');
        }

        res.send('Task updated successfully.');
    } catch (error) {
        res.status(500).send('Error updating task: ' + error.message);
    }
});

// Delete a task
app.delete('/entries/:id', authenticateJWT, async (req, res) => {
    try {
        const entry = await Entry.findByIdAndDelete(req.params.id);

        if (!entry) {
            return res.status(404).json({ message: 'Entry not found' });
        }

        if (entry.userId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'You are not authorized to delete this entry' });
        }

        res.status(200).json({ message: 'Entry deleted successfully' });
    } catch (error) {
        console.error(error); // Log error for debugging
        res.status(500).json({ message: 'Error deleting entry: ' + error.message });
    }
});


// Start the server
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log('Server running on port', port);
});
app.get('/', (req, res) => {
    res.send('Welcome to the API!');
});

