var bodyParser = require('body-parser'),
	express = require('express'),
	ejs = require('ejs'),
	methodOverride = require('method-override'),
	db = require("./models");
	session = require('express-session'),
	pg = require("pg"),
	app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// for express-session
app.use(session({
  secret: 'super secret', // you'll want to hide this -- we'll discuss later
  resave: false,		 // the secret stays same for all of use of app
  saveUninitialized: true
}));
// AUTHENTICATION ROUTES
// let's make our own middleware
// it runs this with every request
// 
app.use("/", function (req, res, next) {
    // the req is the incoming req
    // and the login key is what we made up
    
    // 1st function
    req.login = function (user) {
        // set the value on session.userId
        req.session.userId = user.id; // comes from app.use(session)
    				//^ this is a key that were making up right here

    };
    
  // 2nd function. So user has logged in at this pt, and now we check them against
  // the database and if it jives, we can move on, [if not, blah]
  //
  req.currentUser = function () {  // 'req' is the request object, and we're putting stuff on it
    return db.User.
      find({
        where: {
          id: req.session.userId
       }
      }).
      then(function (user) {
        req.user = user;
        return user;
      })
  };
  //3rd fucntion - logout
  req.logout = function () {
    req.session.userId = null;
    req.user = null;
  }
   next(); // tells us to go to next middleware 
});


// this is a first route
app.get("/signup", function (req, res) {
  res.send("Coming soon");
});

// what's next is after someone's submitted 
//stuff
// remember to have Method=POST and action=users 
//for the form related to this
app.post('/users', function(req, res) {
	var user = req.body.user;

	db.User.
		createSecure(user.email, user.password).
		then(function() {
			res.send('Youre signed up');
		});
});

// this tells us we need a login view
app.get("/login", function (req, res) {
  res.render("login");
});

// login will authenticate a User
app.post("/login", function (req, res) {
	var user = req.body.user; // which is gotten from user putting in data

	db.User.
	authenticate(user.email, user.password).
	then(function(user) { //put in (user) bc it's a promise
		req.login(user); // see line 28
		res.redirect('/profile');
	});
});	




	// bc we want the profile page to be visible to only the logged in user
app.get("/profile", function (req, res) {
  req.currentUser()
    .then(function (user) {
    	console.log("\n\n\n\n\n\nWHAT",user);
      res.render("profile.ejs", {user: user});
    })
});

// ARTICLE ROUTES
app.get('/articles', function(req,res) {
  db.Article
  	.findAll({ include: db.Author })
  	.then(function(dbArticles) {
  		res.render('articles/index', { articlesList: dbArticles });
  	})
});

app.get('/articles/new', function(req,res) {
	// First, we have to get the authors that we can add to the form as a dropdown
	db.Author.all().then(function(dbAuthors) {
		res.render('articles/new', { ejsAuthors: dbAuthors });		
	});
  
});

app.post('/articles', function(req,res) {
  db.Article
  	.create(req.body.article)
  	.then(function(dbArticle) {
  		res.redirect('/articles');
  	})
});

app.get('/articles/:id', function(req, res) {
  db.Article.find({ where: { id: req.params.id }, include: db.Author })
  	.then(function(dbArticle) {
  		res.render('articles/article', { articleToDisplay: dbArticle });
  	});
  
})

// AUTHORS ROUTES
app.get('/authors', function(req, res) {
	db.Author
		.all()
		.then(function(dbAuthors) {
			res.render('authors/index', { ejsAuthors: dbAuthors} );
		});
});

app.get('/authors/new', function(req, res) {
	res.render('authors/new');
});

app.post('/authors', function(req, res) {
	db.Author
		.create(req.body.author)
		.then(function(dbAuthor) {
			res.redirect('/authors');
		});
});

app.get('/authors/:id', function(req, res) {
	db.Author
		.find({ where: {id: req.params.id}, include: db.Article })
		.then(function(dbAuthor) {
			res.render('authors/author', { ejsAuthor: dbAuthor })
		})
});

app.get('/', function(req,res) {
  res.render('site/index.ejs');
});

app.get('/about', function(req,res) {
  res.render('site/about');
});

app.get('/contact', function(req,res) {
  res.render('site/contact');
});

app.get('/sync', function(req, res) {
	db.sequelize.sync().then(function() {
		res.send("Sequelize Synchronization is Complete!");
	})
});

app.listen(3000, function() {
  console.log('Listening');
});
