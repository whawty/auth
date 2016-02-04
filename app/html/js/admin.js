'use strict';

function admin_init() {
  auth_init()
}

var alertbox = function() {}
alertbox.warning = function (dest, heading, message) {
  $('#' + dest + ' .alertbox').html('<div class="alert alert-warning"><a class="close" data-dismiss="alert" href="#">&times;</a><h4 class="alert-heading">' + heading + '</h4>' + message + '</div>');
}
alertbox.error = function (dest, heading, message) {
  $('#' + dest + ' .alertbox').html('<div class="alert alert-danger"><a class="close" data-dismiss="alert" href="#">&times;</a><h4 class="alert-heading">' + heading + '</h4>' + message + '</div>');
}
alertbox.info = function (dest, heading, message) {
  $('#' + dest + ' .alertbox').html('<div class="alert alert-info"><a class="close" data-dismiss="alert" href="#">&times;</a><h4 class="alert-heading">' + heading + '</h4>' + message + '</div>');
}

/*
 *
 * Login
 *
 */

var auth_username = null;
var auth_admin = false;
var auth_session = null;

function auth_loginSuccess(data) {
   if (data.session) {
     auth_username = data.username;
     auth_admin = data.admin;
     auth_session = data.session;

     sessionStorage.setItem("auth_username", auth_username);
     sessionStorage.setItem("auth_admin", auth_admin);
     sessionStorage.setItem("auth_session", auth_session);

     $('#username-field').html(auth_username);
     if (auth_admin == true) {
       $('#role-field').html("Admin");
     } else {
       $('#role-field').html("User");
     }
     $('#loginbox').slideUp();
     $('#mainwindow').fadeIn();
   } else {
     alertbox.error('loginbox', "Error logging in", data.errorstring);
     auth_cleanup();
   }
}

function auth_loginError(req, status, error) {
   var message = status + ': ' + error;
   if(req.status == 401) {
     message = "username and/or password are wrong!";
   }
   alertbox.error('loginbox', "Error logging in", message);
   $("#password").val('');
}

function auth_logout() {
  auth_cleanup();

  $(".alert").alert('close');
  $("#username").val('');
  $("#password").val('');
  $("#mainwindow").fadeOut();
  $('#username-field').html('');
  $('#role-field').html('');
  $('#loginbox').slideDown();
}

function auth_init() {
  auth_username = sessionStorage.getItem("auth_username");
  auth_admin = sessionStorage.getItem("auth_admin");
  auth_session = sessionStorage.getItem("auth_session");

  if(auth_session && auth_username) {
    $("#loginbox").hide();
    $('#username-field').html(auth_username);
    if (auth_admin == true) {
      $('#role-field').html("Admin");
    } else {
      $('#role-field').html("User");
    }
  } else {
    $("#mainwindow").hide();
  }
  $("#loginform").submit(function(event) {
    event.preventDefault();
    var data = JSON.stringify({ username: $("#username").val(), password: $("#password").val() })
    $.post("/api/authenticate", data, auth_loginSuccess, 'json')
        .fail(auth_loginError)
  });
}

function auth_cleanup() {
  sessionStorage.removeItem("auth_username");
  sessionStorage.removeItem("auth_admin");
  sessionStorage.removeItem("auth_session");

  auth_username = null;
  auth_admin = null;
  auth_session = null;

  $("#username").val('').focus();
  $("#password").val('');
}
