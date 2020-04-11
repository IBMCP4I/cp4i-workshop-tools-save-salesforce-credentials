/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var LdapStrategy = require('passport-ldapauth');
var logger = require('morgan');
const axios = require('axios');
const Base64 = require('js-base64').Base64;
require('dotenv').config();

const OPENSHIFT_API_BASE = process.env.OPENSHIFT_API_BASE;
const OPENSHIFT_TOKEN = process.env.OPENSHIFT_TOKEN;


var ldapOpts = {
	   server: {
			 url: process.env.LDAP_URL,
			 bindDN: process.env.LDAP_BIND_DN,
			 bindCredentials: process.env.LDAP_BIND_CREDENTIALS,
			 searchBase: process.env.LDAP_SEARCH_BASE,
			 searchFilter: process.env.LDAP_SEARCH_FILTER
		 }

};

var app = express();

passport.use(new LdapStrategy(ldapOpts));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Middleware to check if user is authenticated
var ensureLoggedIn = function (req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login')
};

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(cookieParser());
app.use(session({
	secret: 'secrets that are truly secure are very hard to come up with',
	resave: true,
	saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

//app.use(express.static(path.join(__dirname, 'public')));

// Main page of app reset form values
app.get('/protected',  ensureLoggedIn, function(request, response) {
   response.render('index',{ user: request.user.uid,
	                           username: "",
													   password: "",
													   clientid: "",
													   clientsecret:"",
														 sectoken:"",
														 statusmsg:"",
														 errormsg:""
													 });
});


// Handle form submission
// 1) Validate Salesforce credentials
// 2) Create OpenShift secret
app.post('/protected',  ensureLoggedIn, function(request, response) {
		var sfOptions = {
			url: request.body.loginurl + '/services/oauth2/token',
			headers: { "Content-Type"  : "application/x-www-form-urlencoded"
			},
			responseType: 'json',
			data:  `username=${encodeURIComponent(request.body.username)}&password=${encodeURIComponent(request.body.password+request.body.sectoken)}&client_id=${encodeURIComponent(request.body.clientid)}&client_secret=${encodeURIComponent(request.body.clientsecret)}&grant_type=password`,
			method: 'POST'
		};
		console.log('axios call to sf '  + JSON.stringify(sfOptions));

    // Validate Salesforce credentials
		axios(sfOptions).then(function(body){
				console.log('validation success ');

				const secretData=`---
accounts:
  salesforce:
    - credentials:
        authType: "oauth2Password"
        username: "${request.body.username}"
        password: "${request.body.password}${request.body.sectoken}"
        clientIdentity: "${request.body.clientid}"
        clientSecret: "${request.body.clientsecret}"
      endpoint:
        loginUrl: "${request.body.loginurl}"
      name: "${request.user.uid}"`

				const k8sSecret = {
				  kind: "Secret",
				  apiVersion: "v1",
				  metadata: {
						 name:  request.user.uid + '-sf-connect',
				     namespace: "ace"
				  },
				  data: {
						credentials: Base64.encode(secretData)
				  },
				  type: "Opaque"
				};


				const openShiftOptions = {
						url: OPENSHIFT_API_BASE + '/api/v1/namespaces/ace/secrets',
						headers: { Authorization  : `Bearer ${OPENSHIFT_TOKEN}` },
						responseType: 'json',
						data:  k8sSecret,
						method: 'POST'
				};
				 // Create OpenShift secret
				 // Clear form values if successful
				axios(openShiftOptions).then(function(body){
						response.render('index',{ user: request.user.uid,
																			username: "",
																			password: "",
																			clientid: "",
																			clientsecret: "",
																			sectoken: "",
																			statusmsg: "Successfully saved the Salesforce credentials as a K8s secret " +  request.user.uid + '-sf-connect',
																			errormsg: ""
																		});
        // If we get here it means there's an openShift problem
				// eg invalid  token or OpenShift cluster is down
				}).catch(function(error){
					 console.log('create secret failed');
					 console.log("error calling k8s api " + error.toString());
						response.render('index',{ user: request.user.uid,
																		 username: request.body.username,
																		 password: request.body.password,
																		 clientid: request.body.clientid,
																		 clientsecret: request.body.clientsecret,
																		 sectoken: request.body.sectoken,
																		 statusmsg: '',
																		 errormsg:'Error storing Salesforce credentials as OpenShift secret. ' + error.toString()
																	 });
				});

		// If we get here it means there's a Salesforce auth problem
		}).catch(function(error){
					// Return form values so user can correct and try again
					console.log('validation failed');
					console.log("error calling sf api " + error.toString());
					response.render('index',{ user: request.user.uid,
																	 username: request.body.username,
																	 password: request.body.password,
																	 clientid: request.body.clientid,
																	 clientsecret: request.body.clientsecret,
																	 sectoken: request.body.sectoken,
																	 statusmsg: '',
																	 errormsg:'Error validating Salesforce credentials. Enter valid credentials and try again.'
																 });

		});

});


app.get('/login', function(request, response) {

  response.render('login');

});

// Handle POST request to authorize user
app.post('/auth', passport.authenticate('ldapauth', { failureRedirect: '/login?loginerror=true' }), function (req, res) {
	 console.log('log in successful');
   res.redirect('/protected');
});


app.get('/logout', ensureLoggedIn, function(request, response) {
	  request.logout();
    request.session.destroy((err) => {
         if(err) {
             return next(err);
         }
         response.redirect('/login');
     });
});

app.get('/', function(request, response) {

   response.redirect('/protected');

});


app.use(express.static(path.join(__dirname, 'public')));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
