const express =require('express')
const app = express()
const path=require('path')
const mongoose=require('mongoose')
const passport= require('passport')
const flash = require('connect-flash')
const morgan = require('morgan')
const cookieParser=require('cookie-parser')
const bodyParser=require('body-parser')
const session = require('express-session')
const {url}=require('./config/database')
// mongoose.connect(url,{
//     useMongoClient:true
// })
mongoose.connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Connected to MongoDB');
})
.catch(error => {
    console.error('Error connecting to MongoDB:', error);
});


// Resto de tu código de la aplicación


require('./config/passport')(passport)

//settings
app.set('port',process.env.PORT||3000)
app.set('views',path.join(__dirname,'views'))
app.set('view engine', 'ejs');

//middlewares
app.use(morgan('dev'))
//  
app.use(bodyParser.urlencoded({extended:false}))
app.use(session({
    secret:'palabrasecreta',
    resave:false,
    saveUninitialized:false,
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

//routes
require('./app/routes')(app,passport)

//static files

app.use(express.static(path.join(__dirname,'public')))



app.listen(app.get('port'),()=>{
    console.log('server on port ', app.get('port'))
})