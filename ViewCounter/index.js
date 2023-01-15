const express = require('express')
const app = express()
app.use(express.json())
const viewCounter = require('./middleware/viewcounter')

app.listen(3000, ()=>{
    console.log("Server Started...");
})

app.use(viewCounter)

const routes = require('./routes/routes')
app.use('/api', routes)



