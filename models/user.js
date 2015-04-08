var bcrypt = require("bcrypt");
var salt = bcrypt.genSaltSync(10);

module.exports = function (sequelize, DataTypes){
  var User = sequelize.define('User', {

    // START OF ATTRIBUTES
    email: { 
      type: DataTypes.STRING, 
      unique: true, 
      validate: {
        len: [6, 30], // <-- validates length (by using a Sequelize API)
      }
    },
    passwordDigest: {
      type:DataTypes.STRING,
      validate: {
        notEmpty: true // <-- vaidates presence of password
      }
    }
  },

  // END OF ATTRIBUTES

  {
    instanceMethods: {
      // these run on a particular user, ex, an instance
      checkPassword: function(password) { // bill.checkPassword("foo") would check 2 c if that was the correct pas for the "bill" instance
        // checkPassword belongs to the instances
    
        return bcrypt.compareSync(password, this.passwordDigest);
      }
    },
    classMethods: {
// these run on User, ex, db.User.createSecure("blah@gmail.com", "blah"), which is the constructor

      encryptPassword: function(password) { // this is a helper function/method for createSecure
        var hash = bcrypt.hashSync(password, salt);
        return hash;
      },

      // START HERE
      createSecure: function(email, password) {
        // check the password length 

        if(password.length < 6) {
          throw new Error("Password too short");

          // then return the created Object
        }
        return this.create({
          email: email,
          passwordDigest: this.encryptPassword(password)
                            // encryptPassword calls bcrypt on password (see Line 38)

        });

      },
      authenticate: function(email, password) {
        // find a user in the DB
        return this.find({
          where: {
            email: email
          }
        }) 
        .then(function(user){
          if (user === null){
            throw new Error("Username does not exist");
          }
          else if (user.checkPassword(password)) { // user is lowercase bc it's an instance
            //makes sure that the password is the correct one

            return user;
          }

        });
      }

    } // close classMethods
  }); // close define user
  return User;
}; // close User function