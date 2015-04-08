# Making Headlines
## ExpressJS

### Notes

Please [let me know](mailto:brett.levenson@ga.co) if there are any issues with the set up instructions or you have questions about the lab. I'll be on Slack for a while.

Just like last night, this repo has two branches: `master` and `solutions`. Solutions contains my solution to the lab, but you should complete your work in the `master` branch.

For those who weren't clear on how to switch branches last night (if you want to peek at the solution or open the solution with `nodemon`), here's a quick tutorial:

After forking and cloning the repo (or if you already did that last night, just make sure that before running the command below you have `cd`'d into the `express_labs` directory that was created when you cloned the repository).

```bash
git branch solutions origin/solutions # Creates a local branch that contains the solution I created

# Then, to switch to solutions:
git checkout solutions

# To switch back to master
git checkout master
```

Also, see the instructions below on how to update your `express_labs` repo with tonight's lab.

### Background

<img src="daily_planet.jpg">

Weclome to the daily planet, we need your superhuman developer skills to help us share news with the world. We've seen that you have some express knowledge and need you to make us a mock website as soon as possible.

### App Set Up

This repo is just a copy of the solution to last night's homework (which asked you to build associations between authors and articles for the daily planet).

If you finished last night's homework, you can start just keep working on what you already created (although you might want to copy the entire directory before you start). But, if you'd rather just start with the solution I created for yesterday's homework, feel free to fork and clone the repo again to get tonight's homework.

```bash
git clone https://<path_to_forked_repo_on_github>
```

Instead of forking again, you could also do the following at a bash prompt:
```bash
cd express_labs # move into the directory where you cloned the repo for last night's homework

# Add SF-WDI-17 organization's repo so you can pull from us into your forked copy:
git remote add upstream https://github.com/sf-wdi-17/express_labs.git # make sure git isn't reporting any errors, and then do:

# Now you get the updates to the repo and merge them for each branch
git fetch upstream # This will grab the latest updates
git checkout master # Switch to master branch
git merge upstream/master # merge the latest into your local copy
git checkout solutions # switch to solutions branch
git merge upstream/solutions # merge the solution for tonight into your local copy

# Finally, switch back to master branch to start working
git checkout master

# Open sublime
cd alphitomorphous-antiminsion-app # yep, you read that right
subl .
```

Forking again is ok, but option 2 will be better in the long run as you'll be able to get each night's homework (for a while anyway) by just running 'git fetch upstream'

### DB Set Up

You should have created the DB for this project last night, so you don't have to do any additional DB set up if you **don't want to**—but, if you'd like to start with a fresh DB for some reason, you can run the following:

```bash
createdb alphitomorphous-antiminsion-app && psql -d alphitomorphous-antiminsion-app -a -f baalshem-adrenotropic-db.sql
```

If you decide to create a new DB using the code above, **don't forget** to modify `config/config.json` and change it to match:

```json
  "development": {
    "database": "alphitomorphous-antiminsion-app",
    "host": "127.0.0.1",
    "dialect": "postgres"
  },
```

### What You Will Be Responsible For:

Starting with either **your solution to last night's lab** or the **master branch of alphitomorphous-antiminsion-app** you should be looking to get user authentication working for *The Daily Planet*.

Which means you'll have to:

#### Create a User Model

Create a User model with the following attributes:

 - email
 - passwordDigest

Generate this model using `sequelize model:create`.

Don't forget to **run `sequelize db:migrate`** after you've generated your `User` model.

#### Routes

By referring to Del's lesson notes from today, create the necessary routes so that someone coming to *The Daily Planet's* web site can:

 - Create a new User
 - Login as a new User
 - View a user's profile

You'll also need to create the relevant actions inside these routes to:

 - Store a new user in the database
 - Authenticate a user at log-in
 - Store an authenticated user in a session
 - Render the user profile

#### Navigation

Add some navigation to the **site index** `view` to make it easy for a visitor to perform these user actions.

#### Views

You're going to need a bunch of new views that you'll place in `views/users/` to render a user profile, render a user creation form, and render a user login form, etc.

#### Bonus

If you want to try to implement **Authorization** tonight, you're welcome to try. There are notes about it in our notes repo under today's `dusk` lesson.

 - This should be set up such that:
   - One `User` is associated with one `Author`
   - A `User` can only edit an article that he/she created.
   - When created, an `Article` knows who its `Author` and `User` is.

> Last updated by Brett Levenson on April 7, 2015.
