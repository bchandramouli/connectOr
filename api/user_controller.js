'use strict';

var user = require('./user_model');
var passport = require('passport');
/* config is used to get the secrets... */
var config = require('../../config/environment');
var jwt = require('jsonwebtoken');

var validationError = function(res, err) {
    return (res.json(422, err));
};

/* 
 * Get list of users
 * restriction: 'admin'
 */
exports.index = function(req, res) {
    User.find({}, '-salt -hashedPassword', function (err, users) {
        if (err) return (res.send(500, err));
        res.json(200, users);
    });
};

 /*
  * Create a new user
  */
exports.create = function (req, res, next) {
    var newUser = new User(req.body);
    newUser.provider = 'local';
    newUser.role = 'user';
    newUser.save(function (err, user) {
        if (err) return(validationError(res, err));
        var token = jwt.sign({_id: user._id},
                             config.secrets.session,
                             {expiresInMinutes: 60*5});
        res.json({token: token});
    });
};
