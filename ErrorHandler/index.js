const express = require('express')
const app = express()
const errorHandler = require('./middleware/errorhandler')
const routes = require('./routes/routes')
app.use(express.json())

app.listen(3000, ()=>{
    console.log("Server started");
    
})
app.use(errorHandler)
app.use('/api', routes)

// const routes = require('./routes/routes')