const jwt = require("jsonwebtoken")
const verifyToken = (req, res, next)=>{
    const token = req.body.token || req.query.token || req.headers["x-access-token"] || req.headers["token"]

    if(!token){
        return res.status(403).send("A token is required")
    }

    try{
        const decoded = jwt.verify(token, process.env.JWT_TOKEN)
        req.user = decoded
        console.log({decoded});
    }catch(err){
        return res.status(401).send("Invalid Credentials")
    }
    return next()
} 

module.exports = verifyToken