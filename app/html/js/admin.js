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
     sessionStorage.setItem("auth_admin", (auth_admin) ? "true" : "false");
     sessionStorage.setItem("auth_session", auth_session);

     $('#username-field').html(auth_username);
     if (auth_admin == true) {
       $('#role-field').html("Admin");
     } else {
       $('#role-field').html("User");
     }
     $('#loginbox').slideUp();
     $('#mainwindow').fadeIn();
     main_init();
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
  auth_admin = (sessionStorage.getItem("auth_admin") == "true") ? true : false;
  auth_session = sessionStorage.getItem("auth_session");

  if(auth_session && auth_username) {
    $("#loginbox").hide();
    $('#username-field').html(auth_username);
    if (auth_admin == true) {
      $('#role-field').html("Admin");
    } else {
      $('#role-field').html("User");
    }
    main_init();
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
  auth_admin = false;
  auth_session = null;

  $("#username").val('').focus();
  $("#password").val('');
}

/*
 *
 * Main
 *
 */

function getRoleLabel(admin) {
  if (admin == true) {
    return $('<span>').addClass("label").addClass("label-danger").text("Admin")
  } else {
    return $('<span>').addClass("label").addClass("label-success").text("User")
  }
}

function getBoolIcon(flag) {
  if (flag == true) {
    return $('<span>').addClass("glyphicon").addClass("glyphicon-ok-sign").css("color", "#5cb85c").css("font-size", "1.4em");
  } else {
    return $('<span>').addClass("glyphicon").addClass("glyphicon-remove-sign").css("color", "#d9534f").css("font-size", "1.4em");
  }
}

function main_userlistSuccess(data) {
  $('#user-list tbody').find('tr').remove();
  for (var user in data.list) {
    var row = $('<tr>').append($('<td>').text(user))
        .append($('<td>').addClass("text-center").append(getRoleLabel(data.list[user].admin)))
        .append($('<td>').addClass("text-center").append(getBoolIcon(data.list[user].valid)))
        .append($('<td>').addClass("text-center").append(getBoolIcon(data.list[user].supported)))
        .append($('<td>').text(data.list[user].formatid))
        .append($('<td>').text(data.list[user].formatparams))
        .append($('<td>').addClass("text-center").text("<here be buttons>"))
    $('#user-list > tbody:last').append(row);
  }
}

function main_userlistError(req, status, error) {
  var data = JSON.parse(req.responseText);
  var message = status + ': ';
  if (data.error != "") {
    message += data.error;
  } else {
    message += error;
  }
  alertbox.error('mainwindow', "Error fetching user list", message);
}

function main_updateUserlist() {
  var data = JSON.stringify({ session: auth_session, })
  $.post("/api/list-full", data, main_userlistSuccess, 'json')
          .fail(main_userlistError)
}

function main_init() {
  if (auth_admin == true) {
    $("#admin-view").show();
    $("#user-view").hide();
    main_updateUserlist();
  } else {
    $("#admin-view").hide();
    $("#user-view").show();
    alertbox.warning('mainwindow', "not yet implemented", "The user view has not been implemented yet");
  }
}
