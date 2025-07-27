// server.js

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const validator = require('validator');
const { PhoneNumberUtil } = require('google-libphonenumber');
require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = process.env.PORT || 3000;
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Database Connection Pool ---
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'vendorfresh_db',
    password: process.env.DB_PASSWORD || 'your_password', // IMPORTANT: Change this for production!
    port: 5432,
});

pool.connect(err => {
    if (err) {
        console.error('Database connection error', err.stack);
    } else {
        console.log('Successfully connected to PostgreSQL database.');
    }
});

const phoneUtil = PhoneNumberUtil.getInstance();

// --- API Endpoints ---

// SIGN UP Endpoint
app.post('/signup', async (req, res) => {
    const { full_name, email, phone_number, password } = req.body;

    if (!full_name || !phone_number || !password) {
        return res.status(400).json({ error: 'Full name, phone number, and password are required.' });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }
    if (email && !validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }
    try {
        const parsedPhone = phoneUtil.parseAndKeepRawInput(phone_number, 'IN');
        if (!phoneUtil.isValidNumber(parsedPhone)) {
            return res.status(400).json({ error: 'Invalid phone number.' });
        }
    } catch (e) {
        return res.status(400).json({ error: 'Invalid phone number format.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUserQuery = `
            INSERT INTO users (full_name, email, phone_number, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING id;
        `;
        const result = await pool.query(newUserQuery, [full_name, email || null, phone_number, hashedPassword]);
        res.status(201).json({ message: 'Account created successfully!', userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'An account with this email or phone number already exists.' });
        }
        console.error('Signup Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});

// LOGIN Endpoint
app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Missing identifier or password' });
    }

    try {
        const findUserQuery = `
            SELECT * FROM users 
            WHERE LOWER(email) = LOWER($1) OR phone_number = $1
        `;
        const { rows } = await pool.query(findUserQuery, [identifier]);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];

        if (!user.password_hash) {
            return res.status(401).json({ error: 'This account was created with Google. Please sign in using your Google account.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            const cartQuery = 'SELECT cart_data FROM carts WHERE user_id = $1';
            const cartResult = await pool.query(cartQuery, [user.id]);
            const cart = cartResult.rows.length > 0 ? cartResult.rows[0].cart_data : {};

            const userInfo = { id: user.id, full_name: user.full_name, email: user.email, phone_number: user.phone_number };
            res.status(200).json({ message: 'Login successful!', user: userInfo, cart: cart });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});

// GOOGLE AUTHENTICATION ENDPOINT
app.post('/auth/google', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ error: 'Google token is missing.' });
    }
    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { sub: google_id, email, name: full_name } = payload;

        let userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user = userResult.rows[0];

        if (!user) {
            const newUserQuery = `INSERT INTO users (full_name, email, google_id) VALUES ($1, $2, $3) RETURNING *;`;
            const newResult = await pool.query(newUserQuery, [full_name, email, google_id]);
            user = newResult.rows[0];
        } else {
            if (!user.google_id) {
                await pool.query('UPDATE users SET google_id = $1 WHERE id = $2', [google_id, user.id]);
            }
        }

        const cartQuery = 'SELECT cart_data FROM carts WHERE user_id = $1';
        const cartResult = await pool.query(cartQuery, [user.id]);
        const cart = cartResult.rows.length > 0 ? cartResult.rows[0].cart_data : {};

        const userInfo = { id: user.id, full_name: user.full_name, email: user.email, phone_number: user.phone_number };
        res.status(200).json({ message: 'Google Sign-In successful!', user: userInfo, cart: cart });

    } catch (err) {
        console.error('Google Auth Error:', err);
        res.status(401).json({ error: 'Invalid Google token. Please sign in again.' });
    }
});

// CART PERSISTENCE ENDPOINT
app.post('/cart/:userId', async (req, res) => {
    const { userId } = req.params;
    const { cart } = req.body;

    if (cart === undefined) {
        return res.status(400).json({ error: 'Cart data is missing.' });
    }

    try {
        const upsertQuery = `
            INSERT INTO carts (user_id, cart_data, last_updated)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id)
            DO UPDATE SET cart_data = EXCLUDED.cart_data, last_updated = NOW();
        `;
        await pool.query(upsertQuery, [userId, cart]);
        res.status(200).json({ message: 'Cart updated successfully.' });
    } catch (err) {
        console.error('Cart Update Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred while updating the cart.' });
    }
});

// **FIXED** USER PROFILE UPDATE ENDPOINT
app.post('/user/:userId', async (req, res) => {
    const { userId } = req.params;
    const { full_name, email, phone_number, password } = req.body;

    // --- Basic Validation ---
    if (!full_name || !phone_number) {
        return res.status(400).json({ error: 'Full name and phone number are required.' });
    }
    if (email && !validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }
    if (password && password.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    try {
        // --- Build the UPDATE query dynamically ---
        const queryParams = [full_name, email || null, phone_number];
        let setClauses = 'SET full_name = $1, email = $2, phone_number = $3';
        
        // **NEW**: If a new password is provided, hash it and add it to the query
        if (password) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            queryParams.push(hashedPassword);
            setClauses += `, password_hash = $${queryParams.length}`;
        }
        
        // Add the WHERE clause
        queryParams.push(userId);
        const updateUserQuery = `
            UPDATE users
            ${setClauses}
            WHERE id = $${queryParams.length}
            RETURNING id, full_name, email, phone_number;
        `;

        const { rows } = await pool.query(updateUserQuery, queryParams);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        // Return the updated user information (without the password hash)
        res.status(200).json({ message: 'Profile updated successfully!', user: rows[0] });
    } catch (err) {
        // Handle unique constraint violations (e.g., email or phone already taken)
        if (err.code === '23505') {
            return res.status(409).json({ error: 'This email or phone number is already in use by another account.' });
        }
        console.error('Profile Update Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred while updating profile.' });
    }
});


// --- Start the Server ---
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
