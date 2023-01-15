const express = require('express')
const mongoose = require('mongoose')
const app = express()
const jwt = require('jsonwebtoken')
app.use(express.json())


app.listen(3000, ()=>{
    console.log("Server Started...");
})

require('dotenv').config()
const mongoString = process.env.DATABASE_URL
mongoose.connect(mongoString)
const db = mongoose.connection

db.on('error', (err)=>{
    console.log(err);
})

db.once('connected', ()=>{
    console.log('Database Connected');
})

const routes = require('./routes/routes')
app.use('/api', routes)
