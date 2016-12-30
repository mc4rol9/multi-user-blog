# Multi User Blog
This is a multi user blog project built with Google App Engine SDK for Python.
It's a basic blog with a front page that lists all the blog posts that have
their own pages with Comments and Likes. Users must to be registered and
logged in in order to post, comment and like another's posts.
All security issues were handled for user registration and login, with cookies
setted correctly and hashed stored passwords.

You can see a live version of this project running [here](http://udacity-150204.appspot.com/)

**_This is the third project submission for Udacity Full Stack Web Developer Nanodegree Program._**

## Installation
In order to run and make changes to this project, you'll need:
- [Python](https://www.python.org/)
- [Google App Engine SDK for Python](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python)
- [Google App Engine Account](https://console.cloud.google.com/appengine)
- Some browser

## Usage
To run this project locally:
- Make sure you have the Google App Engine SDK intalled and running
- Download all the files to your machine
- Starts the Google Cloud SDK Shell
- Inside the project directory use the command `dev_appserver.py .`
- Opens your localhost in a browser: the correct address will appear after
server starts in Shell. Probably <strong>http://localhost:8080</strong>.

To send/deploy this project to you Google Cloud App Engine:
- Starts the Google SDK Shell
- Inside the project directory use the command `gcloud app deploy`
- Follow the steps
- To open the cloud app in your browser use `gcloud app browse`

## Files
Understanding the files:

`blog.py`
This is the file with all the project scripts.

`app.yaml`
This is the configuration file for the app.

`the templates folder`
These are the HTML files for all the pages of the project.

`the static folder`
Just the CSS file and the Favicon icon.

## Built With
- [Python](https://www.python.org/)
- [Google App Engine SDK for Python](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python)
