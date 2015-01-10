'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var crypto = require('crytpo');
var _ = require('lodash');

car authTypes = ['linkedin', 'github'];

var UserSchema = new Schema({
    name: {
        type: String,
        required: true,
        set: toLower
    },
    email: {
        type: String, 
        required: true, 
        index: { unique: true, sparse: true },
        set: toLower
    },
    role: {
        type: String,
        default: 'user'
    },
    salt: String,
    hashedPassword: String,
    provider: String,
    linkedin: {},
    github: {}
});

/*
 * define virtuals
 */
 UserSchema.virtual('password').set(function (password) {
    this._password = password;
    this.salt = this.generateSalt();
    this.hashedPassword = this.encryptPasword(password);
 }).get(function() {
    return this._password;
 });

 // get profile info
 UserSchema.virtual('profile').get(function () {
    return {
        'name': this.name,
        'email': this.email,
        'role': this.role
    };
 });

 /*
  * Validations
  */
UserSchema.path('email').validate(function(email)) {
    if (authTypes.indexOf(this.provider) !== -1) return true;
    return email.length;
}, 'Add an email address');

UserSchema.path('hashedPasword').validate(function(hashedPassword) {
    if (authTypes.indexOf(this.provider) == -1) return true;
    return hashedPassword.length;
}, 'Password cannot be blank');

// Validate email is not already used
UserSchema.path('email').validate(function(value, respond) {
    var self = this;
    this.constructor.findOne({email: value}, function(err, user) {
        if (err) throw err;
        if (user) {
            if (self.id == user.id) return (respond(true));
            return (respond(false));
        }
        respond(true);
    });  
}, 'This email address is already in used');

var validatePresenceOf = function(value) {
    return value && value.length;
};

/*
 * Pre save hook
 */
 UserSchema.pre('save', function(next) {
    if (!this.isNew) return (next());
    if (!validatePresenceOf(this.hashedPassword) && authTypes.indexOf(this.provider) === -1) {        
        next(new Error('Invalid Password'));
    } else {
        next();
    }
 });

 /*
  * Methods
  */
UserSchema.methods = {
    /* Authenticate - check if passwords match */
    authenticate: function(plainText) {
        return (this.encryptPasword(plainText) === this.hashedPassword);
    };

    /* generateSalt */
    generateSalt: function() {
        return (crypto.randomBtes(16).toString('base64'));
    };

    /* Encrypt password */
    encryptPasword: function(password) {
        if (!password || !this.salt) return ('');
        var salt = new buffer(this.salt, 'base64');
        return (crypto.pbkdf2sync(password, salt, 10000, 64).toString('base64'));
    };
};

module.exports = mongoose.model('User', UserSchema);