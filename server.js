// Require Dependencias
var express = require('express');
var mongoose = require('mongoose');
var methodOverride = require('method-override');
var bodyParser = require('body-parser');
var path = require('path');
var favicon = require('favicon');
var fs = require('fs');
var multer = require('multer');
var _ = require('lodash');
var jwt = require('jwt-simple');
var bcrypt = require('bcrypt');

//modelos
var User = require('./models/user');



// db spoof prov.
// var users = [{username: 'danielr50', password: '$2a$10$6Mvt2AsHZUWuoNhrPxkoeedHtsjSUkC1AqcarcyfIWjVI5.IQu9kS'}]
var secretKey = 'superSecretKey';

// encuentra en el modelo users el username con valor username
function findUserByUsername(username){
  return _.find(users, { username: username});
}

// valida si pass esta bien 
function validateUser(user, password, cb){
  // user.password === password; // devuelve un bool
  bcrypt.compare(password, user.password, cb);
}
  
// fin token libro

// require mongo
var db = require('./db/db.js');
db.conectar();
var app = express();

// require todos los modelos
fs.readdirSync(__dirname+ '/models').forEach(function(filename){
  if (~filename.indexOf('.js')) require(__dirname+'/models/'+filename);
});


// // view engine setup
// app.set('views', path.join(__dirname, 'views'));
// app.set('view engine', 'jade'); 

app.use(multer({ dest: './uploads/'}));

// middlewares
app.use(bodyParser.urlencoded({ extended: false}));
app.use(bodyParser.json());
app.use(methodOverride(function(req, res){
      if (req.body && typeof req.body === 'object' && '_method' in req.body) {
        // look in urlencoded POST bodies and delete it
        var method = req.body._method
        delete req.body._method
        return method
      }
}));

// CORS
app.use(function(req, res, next){
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,Content-Type,Authorization');
  next();
});

// login - check if credentials are valid - crear un nuevo token
// esto va pegado al action=/session en el form - creo
app.post('/session', function(req, res, next){
User.findOne({ username: req.body.username})
.select('password')
.exec(function(err, user){
  if(err) {return next(err)}
  if(!user) {return res.send(401) } 
  //compara contraseñas si usuario es valido y no err  
  bcrypt.compare(req.body.password, user.password, function(err, valid){
    if(err) { return next(err)}
    if(!valid){ return res.send(401)} //unathorized
    // crea el toke - si contraseñas son iguales y no err
    var token = jwt.encode({username: user.username}, secretKey);
    // devuelve el token con la info del user
    res.json(token);
  });  
});
});

// devuelve el user basado en un token
app.get('/user', function(req, res){
  var token = req.headers['x-auth'];
  //decodifica el token con la secretKey
  var auth = jwt.decode(token, secretKey);
  // pull user info from db
  User.findOne({ username: auth.username }, function(err, user){
    // if (err) next(err);  probar si sirve con esta linea
    //devuelve el objeto user 
    res.json(user);
  });
});

// ruta para crear nuevo user accounts
app.post('/user', function(req, res, next){
  var user = new User({ username: req.body.username})
  bcrypt.hash(req.body.password, 10, function(err, hash){
    user.password = hash;
    user.save(function(err, user){
      if(err){ throw next(err) }
      res.send(201);  
    });
  });
});



// routes API
app.use('/', require('./routes'));


// ERROR HANDLERS

//catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
      res.send('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
    res.send('error', {
    message: err.message,
    error: {}
  });
});


// Start the server
app.set('port', process.env.PORT || 3000);

var server = app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + server.address().port);
});


module.exports = app;