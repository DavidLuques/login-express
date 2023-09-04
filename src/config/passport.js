const localStrategy = require('passport-local').Strategy;
const User = require('../app/models/users');
const passport = require('passport');

module.exports = function(passport) {
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id)
            .then(user => {
                done(null, user);
            })
            .catch(err => {
                done(err, null);
            });
    });

    // Login
    passport.use('local-login', new localStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    }, async function(req, email, password, done) {
        try {
            const user = await User.findOne({ 'local.email': email });

            if (!user) {
                return done(null, false, req.flash('loginmessage', 'No user found!'));
            }

            if (!user.validatePassword(password)) {
                return done(null, false, req.flash('loginmessage', 'Wrong password'));
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }));

    // Sign up users
    passport.use('local-signup', new localStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    }, async function(req, email, password, done) {
        try {
            const existingUser = await User.findOne({ 'local.email': email });

            if (existingUser) {
                return done(null, false, req.flash('signupmessage', 'This email is already taken'));
            } else {
                const newUser = new User();
                newUser.local.email = email;
                newUser.local.password = newUser.generateHash(password);

                await newUser.save();

                return done(null, newUser);
            }
        } catch (err) {
            return done(err);
        }
    }));
};

// Sign up users
// passport.use('local-signup', new localStrategy({
//     usernameField: 'email',
//     passwordField: 'password',
//     passReqToCallBack: true
// }, async function (req, email, password, done) {
//     try {
//         const existingUser = await User.findOne({ 'local.email': email });

//         if (existingUser) {
//             return done(null, false, req.flash('signupmessage', 'This email is already taken'));
//         } else {
//             const newUser = new User();
//             newUser.local.email = email;
//             newUser.local.password = newUser.generateHash(password);

//             await newUser.save();

//             return done(null, newUser);
//         }
//     } catch (err) {
//         return done(err);
//     }
// }));

