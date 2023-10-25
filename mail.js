const nodemailer = require('nodemailer')
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'koby.davis@ethereal.email',
        pass: '6eH8CggVTFwTtEYVUh'
    }
})

const mail=(mailOptions)=>{
        transporter.sendMail(mailOptions,(error,info)=>{
            if(error){
                console.log(error)
            }else{
                console.log(`Mail Sent to ${mailOptions.to}.`)
            }
        })
}
module.exports = mail