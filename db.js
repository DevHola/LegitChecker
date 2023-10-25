const mongoose = require('mongoose')

const connection = () => {
  mongoose.connect(process.env.mongouri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    family: 4,
    authSource: 'admin'
    // mongodb://adminUser:adminPassword@localhost:27017/?authMechanism=DEFAULT&authSource=ana
  }).then(() => {
    console.log('Connection Established')
  }).catch((error) => {
    console.log(error)
  })
}
module.exports = connection
