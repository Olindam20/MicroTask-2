const mongoose = require('mongoose')
const {isEmail} = require('validator')


const userSchema = mongoose.Schema({
    email:{
        type:'String',
        required:[true, 'Email is Required'],
        validate:{
            validator:isEmail,
            message:(props)=>`${props.value} is not valid email`
        }
    },
    age:{
        type:'double',
        required:[true,'Age is Required']
    },
    password:{
        type:String,
        required:[true, 'Password is required'],
        validate:{
            validator:function (value){
                return value.length >=6
            },
            message:()=>'Password must be more than 6 characters long'
        }
    }
})

module.exports = mongoose.model('User', userSchema)