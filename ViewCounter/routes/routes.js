const express = require('express')
const router = express.Router()
const fs = require('fs')


router.get('/get-views', (req, res)=>{
    const views = fs.readFileSync('./views.json', 'utf-8')
    const viewsData = JSON.parse(views)
    res.status(200).json({
        views:viewsData.views
    })
})


module.exports = router