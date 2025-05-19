const express = require('express');
const config = require('../config');
const router = express.Router();
const MongoClient = require('mongodb').MongoClient;
const mongoSanitize = require('mongo-sanitize');
const rateLimit = require('express-rate-limit');

const url = config.MONGODB_URI;

// Optional: Add basic rate-limiting to prevent abuse
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5,
    message: { status: "Error", message: "Too many login attempts, please try again later." }
});

function validateStringInput(input) {
    return typeof input === 'string' && input.trim().length > 0;
}

// Register customer
router.post('/customers/register', async (req, res) => {
    const name = mongoSanitize(req.body.name);
    const address = mongoSanitize(req.body.address);

    if (!validateStringInput(name) || !validateStringInput(address)) {
        return res.status(400).json({ status: "Error", message: "Invalid input." });
    }

    let client;
    try {
        client = await MongoClient.connect(url, { useNewUrlParser: true });
        const db = client.db(config.MONGODB_DB_NAME);
        const customers = db.collection("customers");

        const newCustomer = { name, address };
        await customers.insertOne(newCustomer);

        res.json({ status: "Success", message: "User registered." });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ status: "Error", message: "Internal server error." });
    } finally {
        if (client) client.close();
    }
});

// Find customer by name
router.post('/customers/find', async (req, res) => {
    const name = mongoSanitize(req.body.name);

    if (!validateStringInput(name)) {
        return res.status(400).json({ status: "Error", message: "Invalid input." });
    }

    let client;
    try {
        client = await MongoClient.connect(url, { useNewUrlParser: true });
        const db = client.db(config.MONGODB_DB_NAME);
        const customers = db.collection("customers");

        const result = await customers.findOne({ name });
        if (!result) {
            return res.status(404).json({ status: "Error", message: "Customer not found." });
        }

        res.json({ status: "Success", data: result });
    } catch (err) {
        console.error("Find error:", err);
        res.status(500).json({ status: "Error", message: "Internal server error." });
    } finally {
        if (client) client.close();
    }
});

// Customer login
router.post('/customers/login', loginLimiter, async (req, res) => {
    const email = mongoSanitize(req.body.email);
    const password = mongoSanitize(req.body.password);

    if (!validateStringInput(email) || !validateStringInput(password)) {
        return res.status(400).json({ status: "Error", message: "Invalid input." });
    }

    let client;
    try {
        client = await MongoClient.connect(url, { useNewUrlParser: true });
        const db = client.db(config.MONGODB_DB_NAME);
        const customers = db.collection("customers");

        const user = await customers.findOne({ email, password });
        if (!user) {
            return res.status(401).json({ status: "Error", message: "Authentication failed." });
        }

        res.json({ status: "Success", user });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ status: "Error", message: "Internal server error." });
    } finally {
        if (client) client.close();
    }
});

module.exports = router;
