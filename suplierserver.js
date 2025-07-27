// server.js (Unified for Vendors & Suppliers)

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config(); // Reads credentials from .env file

const app = express();
const port = 3000; // Running the entire application on a single port

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Database Connection Pool ---
// Connects to your 'supplierdb' using credentials from your .env file
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
});

// --- Database Table Setup ---
const createTables = async () => {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                phone_number VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                price NUMERIC(10, 2) NOT NULL,
                image_url TEXT,
                supplier_id INTEGER REFERENCES users(id) ON DELETE CASCADE
            );
        `);
        console.log('Tables in supplierdb checked or created successfully.');
    } catch (err) {
        console.error('Error creating tables:', err.stack);
    } finally {
        client.release();
    }
};
createTables().catch(console.error);


// --- Unified Auth Endpoints ---

// SIGN UP for BOTH Vendors and Suppliers
app.post('/signup', async (req, res) => {
    const { full_name, email, phone_number, password, role } = req.body;
    if (!full_name || !phone_number || !password || !role) {
        return res.status(400).json({ error: 'Full name, phone, password, and role are required.' });
    }
    if (!['vendor', 'supplier'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role specified.' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUserQuery = `
            INSERT INTO users (full_name, email, phone_number, password_hash, role)
            VALUES ($1, $2, $3, $4, $5) RETURNING id, full_name, role;
        `;
        const result = await pool.query(newUserQuery, [full_name, email || null, phone_number, hashedPassword, role]);
        res.status(201).json({ message: 'Account created successfully!', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'An account with this email or phone number already exists.' });
        console.error('Signup Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});

// LOGIN for BOTH Vendors and Suppliers
app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;
    if (!identifier || !password) return res.status(400).json({ error: 'Missing identifier or password' });
    try {
        const findUserQuery = `SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR phone_number = $1`;
        const { rows } = await pool.query(findUserQuery, [identifier]);

        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });
        
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            const userInfo = { id: user.id, full_name: user.full_name, email: user.email, phone_number: user.phone_number, role: user.role };
            res.status(200).json({ message: 'Login successful!', user: userInfo });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'An unexpected error occurred.' });
    }
});


// --- Product Management Endpoints ---

// GET ALL products for the Vendor portal
app.get('/products', async (req, res) => {
    try {
        const query = `
            SELECT p.id, p.name, p.category, p.price, p.image_url, u.full_name AS supplier_name
            FROM products p
            JOIN users u ON p.supplier_id = u.id
            ORDER BY p.category, p.name;
        `;
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: 'Failed to fetch products.' });
    }
});

// GET products for a SPECIFIC supplier's dashboard
app.get('/suppliers/:supplierId/products', async (req, res) => {
    const { supplierId } = req.params;
    try {
        const result = await pool.query('SELECT * FROM products WHERE supplier_id = $1 ORDER BY name', [supplierId]);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching supplier products:', err);
        res.status(500).json({ error: 'Failed to fetch your products.' });
    }
});

// POST a new product from the Supplier dashboard
app.post('/products', async (req, res) => {
    const { name, category, price, image_url, supplier_id } = req.body;
    if (!name || !category || !price || !supplier_id) return res.status(400).json({ error: 'Missing required product fields.' });
    try {
        const newProductQuery = `
            INSERT INTO products (name, category, price, image_url, supplier_id)
            VALUES ($1, $2, $3, $4, $5) RETURNING *;
        `;
        const result = await pool.query(newProductQuery, [name, category, price, image_url || null, supplier_id]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error adding product:', err);
        res.status(500).json({ error: 'Failed to add product.' });
    }
});

// DELETE a product from the Supplier dashboard
app.delete('/products/:productId', async (req, res) => {
    const { productId } = req.params;
    try {
        const result = await pool.query('DELETE FROM products WHERE id = $1 RETURNING *', [productId]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Product not found.' });
        res.status(200).json({ message: 'Product deleted successfully.' });
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ error: 'Failed to delete product.' });
    }
});


// --- Start the Server ---
app.listen(port, () => {
    console.log(`Unified server is running on http://localhost:${port}`);
});
