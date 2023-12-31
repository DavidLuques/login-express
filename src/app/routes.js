module.exports = (app, passport) => {
    app.get('/', (req, res) => {
        res.render('index')
    })
    app.get('/login', (req, res) => {
        res.render('login', {
            message: req.flash('loginmessage')
        })
    })
    app.post('/login', passport.authenticate('local-login', {
        successRedirect: '/profile',
        failureRedirect: '/login',
        failureFlash: true
    }))

    app.get('/signup', (req, res) => {
        res.render('signup', {
            message: req.flash('signupmessage')
        })
    })
    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/profile',
        failureRedirect: '/signup',
        failureFlash: true
    }));
    app.get('/profile', isLoggedIn, (req, res) => {
        res.render('profile', {
            user: req.user
        })
    })

    app.get('/logout', (req, res) => {
        req.logout(function (err) {
            if (err) {
                //I've to handle the err hre :p
                console.error(err);
            }
            res.redirect('/');
        });
    });
    function isLoggedIn(req, res, next) {
        if (req.isAuthenticated()) {
            return next()
        }
        return res.redirect('/')
    }
}