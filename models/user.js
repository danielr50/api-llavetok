var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var user = new Schema({
	username: String,
	password: {type: String, select: false}
});

module.exports = mongoose.model('User', user);


