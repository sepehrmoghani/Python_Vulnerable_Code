const express = require('express');
const config = require('../config')
const router = express.Router()

const MongoClient = require('mongodb').MongoClient;
const url = config.MONGODB_URI;

router.post('/customers/register', async (req, res) => {

    const client = await MongoClient.connect(url, { useNewUrlParser: true })
        .catch(err => { console.log(err); });
    if (!client) {
        return res.json({ status: "Error" });
    }
    const db = client.db(config.MONGODB_DB_NAME);
    const customers = db.collection("customers")
    
    let myobj = { name: req.body.name, address: req.body.address };
    customers.insertOne(myobj, function (err) {
        if (err) throw err;
        console.log("user registered");
        res.json({ status:"success", "message": "user inserted" })
        db.close();
    });
    
})


// Vulnerable search function
router.post('/customers/find', async (req, res) => {

    const client = await MongoClient.connect(url, { useNewUrlParser: true })
        .catch(err => { console.log(err); });
    if (!client) {
        return res.json({ status: "Error" });
    }
    const db = client.db(config.MONGODB_DB_NAME);
    const customers = db.collection("customers")

    let name = req.body.name
    let myobj = { name: name };
    customers.findOne(myobj, function (err, result) {
        if (err) throw err;
        db.close();
        res.json(result)
    });

  
})

// Vulnerable Authentication
// Authentication Bypass Example
// curl -X POST http://localhost:3000/customers/login/ --data "{\"email\": {\"\$gt\":\"\"} , \"password\": {\"\$gt\":\"\"}}" -H "Content-Type: application/json"

const mongoSanitize = require('mongo-sanitize');

router.post('/customers/login', async (req, res) => {
    const client = await MongoClient.connect(url, { useNewUrlParser: true })
        .catch(err => { console.log(err); });
    if (!client) {
        return res.json({ status: "Error" });
    }
    const db = client.db(config.MONGODB_DB_NAME);
    const customers = db.collection("customers");

    // Sanitize inputs
    const email = mongoSanitize(req.body.email);
    const password = mongoSanitize(req.body.password);

    // Validate that inputs are strings
    if (typeof email !== 'string' || typeof password !== 'string') {
        db.close();
        return res.status(400).json({ status: "Error", message: "Invalid input types." });
    }

    const myobj = { email: email, password: password };
    customers.findOne(myobj, function (err, result) {
        db.close();
        if (err) {
            return res.status(500).json({ status: "Error", message: "Database query failed." });
        }
        if (!result) {
            return res.status(401).json({ status: "Error", message: "Authentication failed." });
        }
        res.json({ status: "Success", user: result });
    });
});


module.exports = router
