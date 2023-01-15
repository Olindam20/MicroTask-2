const express = require('express')
const router = express.Router()
const errorHandler = require('../middleware/errorhandler')



router.get("/error",(req, res, next)=>{
    try{
        console.log("error");
        res.status(400).send("Error here")

    }catch(err){
        next(err)
    }
    
} )




module.exports = router