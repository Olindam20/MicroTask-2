const fs = require('fs')

const viewCounter = (req, res, next)=>{
    console.log("in vc");

    const views = fs.readFileSync('views.json', 'utf-8')
    const viewsData = JSON.parse(views)
    viewsData.views = viewsData.views + 1
    const newData = JSON.stringify(viewsData)
    fs.writeFileSync('views.json', newData)
    
    next()

}

module.exports = viewCounter