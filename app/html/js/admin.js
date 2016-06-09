'use strict';

function admin_init() {
  auth_init()
  main_enablePWChecks();
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
alertbox.success = function (dest, heading, message) {
  $('#' + dest + ' .alertbox').html('<div class="alert alert-success"><a class="close" data-dismiss="alert" href="#">&times;</a><h4 class="alert-heading">' + heading + '</h4>' + message + '</div>');
}


/*
 *
 * Login
 *
 */
var auth_username = null;
var auth_admin = false;
var auth_lastchanged = new Date();
var auth_session = null;

function auth_loginSuccess(data) {
  if (data.session) {
    $("#login-submit").click(); // tell browser to store the password

    auth_username = data.username;
    auth_admin = data.admin;
    auth_lastchanged = new Date(data.lastchanged);
    auth_session = data.session;

    sessionStorage.setItem("auth_username", auth_username);
    sessionStorage.setItem("auth_admin", (auth_admin) ? "true" : "false");
    sessionStorage.setItem("auth_lastchanged", auth_lastchanged.toISOString());
    sessionStorage.setItem("auth_session", auth_session);

    $('#login-box').slideUp();

    $('#username-field').text(auth_username);
    if (auth_admin == true) {
      $('#role-field').text("Admin");
    } else {
      $('#role-field').text("User");
    }
    $('#mainwindow').fadeIn();
    main_init();
  } else {
    alertbox.error('login-box', "Error logging in", data.errorstring);
    auth_cleanup();
  }
}

function auth_loginError(req, status, error) {
  var message = status + ': ' + error;
  if(req.status == 401) {
    message = "username and/or password are wrong!";
  }
  alertbox.error('login-box', "Error logging in", message);
  $("#login-password").val('');
}

function auth_logout() {
  auth_cleanup();

  $(".alert").alert('close');
  $("#login-username").val('');
  $("#login-password").val('');
  $("#mainwindow").fadeOut();
  $('#username-field').text('');
  $('#role-field').text('');
  $('#login-box').slideDown(function() {
    $("#login-username").focus();
  });
}

function auth_init() {
  auth_username = sessionStorage.getItem("auth_username");
  auth_admin = (sessionStorage.getItem("auth_admin") == "true") ? true : false;
  auth_lastchanged = new Date(sessionStorage.getItem("auth_lastchanged"));
  auth_session = sessionStorage.getItem("auth_session");

  if(auth_session && auth_username) {
    $("#login-box").hide();
    $('#username-field').text(auth_username);
    if (auth_admin == true) {
      $('#role-field').text("Admin");
    } else {
      $('#role-field').text("User");
    }
    $("#mainwindow").fadeIn();
    main_init();
  } else {
    $("#login-box").fadeIn();
    $("#mainwindow").hide();
  }
  $("#login-btn").click(function(event) {
    var data = JSON.stringify({ username: $("#login-username").val(), password: $("#login-password").val() })
    $.post("/api/authenticate", data, auth_loginSuccess, 'json').fail(auth_loginError);
  });
  $("#login-username").keypress(function(event) { overrideEnter(event, $("#login-btn")); });
  $("#login-password").keypress(function(event) { overrideEnter(event, $("#login-btn")); });
}

function auth_cleanup() {
  sessionStorage.removeItem("auth_username");
  sessionStorage.removeItem("auth_admin");
  sessionStorage.removeItem("auth_lastchanged");
  sessionStorage.removeItem("auth_session");

  auth_username = null;
  auth_admin = false;
  auth_lastchanged = null;
  auth_session = null;

  $("#login-username").val('');
  $("#login-password").val('');
}


/*
 *
 * Main: admin view
 *
 */
function main_updateSuccess(data) {
  if(data.username == auth_username) {
    $("#changepw-submit").click(); // tell browser to update it's password store, but only if it is ours...
  }
  alertbox.success('mainwindow', "Password Update", "successfully updated password for " + data.username);
  main_updateUserlist()
}

function main_getUpdateButton(user) {
  var btn = $('<button>').addClass("btn").addClass("btn-primary").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>&nbsp;&nbsp;Password')
  return btn.click(function() {
    main_cleanupPasswordModal()

    $('#changepw-userfield').text(user);
    $('#changepw-username').val(user); // tell the browser to update it's password store
    $("#changepw-btn").click(function(event) {
      var newpassword = $("#changepw-password").val()
      var data = JSON.stringify({ session: auth_session, username: user, newpassword: newpassword })
      $.post("/api/update", data, main_updateSuccess, 'json').fail(main_reqError)
      $("#changepw-modal").modal('hide');
    });
    $("#changepw-btn").text("Change");
    $("#changepw-password").keypress(function(event) { overrideEnter(event, $("#changepw-btn")); });
    $("#changepw-password-retype").keypress(function(event) { overrideEnter(event, $("#changepw-btn")); });
    $("#changepw-modal").modal('show');
  });
}

function main_removeSuccess(data) {
  alertbox.success('mainwindow', "Remove User", "successfully removed user " + data.username);
  main_updateUserlist()
}

function main_getRemoveButton(user) {
  var btn = $('<button>').addClass("btn").addClass("btn-danger").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-trash" aria-hidden="true"></span>&nbsp;&nbsp;Remove')
  return btn.click(function() {
    var data = JSON.stringify({ session: auth_session, username: user })
    $.post("/api/remove", data, main_removeSuccess, 'json').fail(main_reqError)
  });
}

function main_setadminSuccess(data) {
  main_updateUserlist()
}

function main_getSetAdminButton(user, oldstate) {
  var btn = $('<button>').addClass("btn").addClass("btn-warning").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-random" aria-hidden="true"></span>&nbsp;&nbsp;Role')
  var newstate = !oldstate;
  return btn.click(function() {
    var data = JSON.stringify({ session: auth_session, username: user, admin: newstate })
    $.post("/api/set-admin", data, main_setadminSuccess, 'json').fail(main_reqError)
  });
}

function main_getRoleLabel(admin) {
  if (admin == true) {
    return $('<span>').addClass("label").addClass("label-primary").text("Admin")
  } else {
    return $('<span>').addClass("label").addClass("label-default").text("User")
  }
}

function main_getBoolIcon(flag) {
  if (flag == true) {
    return $('<span>').addClass("glyphicon").addClass("glyphicon-ok-sign").css("color", "#5cb85c").css("font-size", "1.4em");
  } else {
    return $('<span>').addClass("glyphicon").addClass("glyphicon-remove-sign").css("color", "#d9534f").css("font-size", "1.4em");
  }
}

Number.prototype.pad = function(size) {
  var s = String(this);
  while (s.length < (size || 2)) {s = "0" + s;}
  return s;
}

function getLastChange(lastchange) {
  return $('<string>').addClass("last-change").text(getDateTimeString(lastchange))
}

function main_userlistSuccess(data) {
  $('#user-list tbody').find('tr').remove();
  for (var user in data.list) {
    var row = $('<tr>').append($('<td>').text(user))
        .append($('<td>').addClass("text-center").append(main_getRoleLabel(data.list[user].admin)))
        .append($('<td>').append(getLastChange(new Date(data.list[user].lastchanged))))
        .append($('<td>').addClass("text-center").append(main_getBoolIcon(data.list[user].valid)))
        .append($('<td>').addClass("text-center").append(main_getBoolIcon(data.list[user].supported)))
        .append($('<td>').text(data.list[user].formatid + ' (' + data.list[user].formatparams + ')'))
        .append($('<td>').addClass("text-center").append(main_getSetAdminButton(user, data.list[user].admin))
                                                 .append(main_getUpdateButton(user))
                                                 .append(main_getRemoveButton(user)));
    $('#user-list > tbody:last').append(row);
  }
}

function main_addSuccess(data) {
  // we don't want the browser to update it's password store -> don't submit the form!
  alertbox.success('mainwindow', "Add User", "successfully added user " + data.username);
  main_updateUserlist()
}

function main_setupAddButton() {
  $("#addusername").val('')
  $("#adduserform").submit(function(event) {
    event.preventDefault();
    var user = $("#addusername").val()
    var admin = false
    if ( $('input[name="addrole"]:checked').val()  == "admin") {
      admin = true;
    }
    main_cleanupPasswordModal()

    $('#changepw-userfield').text(user);
    $('#changepw-username').val(''); // we don't want the browser to add this user to it's password store...
    $("#changepw-btn").click(function(event) {
      var newpassword = $("#changepw-password").val()
      var data = JSON.stringify({ session: auth_session, username: user, password: newpassword, admin: admin })
      $.post("/api/add", data, main_addSuccess, 'json').fail(main_reqError)
      $("#changepw-modal").modal('hide');
      $("#addusername").val('');
      $('#changepw-userfield').text('');
      $("#changepw-password").val(''); // we don't want the browser to add this user to it's password store...
      $("#changepw-password-retype").val('');
    });
    $("#changepw-btn").text("Add");
    $("#changepw-password").keypress(function(event) { overrideEnter(event); });
    $("#changepw-password-retype").keypress(function(event) { overrideEnter(event); });
    $("#changepw-modal").modal('show');
  });
}

function main_updateUserlist() {
  var data = JSON.stringify({ session: auth_session, })
  $.post("/api/list-full", data, main_userlistSuccess, 'json').fail(main_reqError)
}

function main_adminViewInit() {
  main_setupAddButton();
  main_updateUserlist();
}


/*
 *
 * Main: user view
 *
 */
function main_userUpdateSuccess(data) {
  $("#changepw-submit").click(); // tell browser to update it's password store
  alertbox.success('mainwindow', "Password Update", "successfully updated password for " + data.username);
}

function main_userViewInit() {
  $("#user-view .username").text(auth_username);
  $("#user-view .lastchange").text(getDateTimeString(auth_lastchanged));
  $('#user-view .btn').click(function() {
    main_cleanupPasswordModal()

    $('#changepw-userfield').text(auth_username);
    $('#changepw-username').val(auth_username); // tell the browser to update it's password store
    $("#changepw-btn").click(function(event) {
      var newpassword = $("#changepw-password").val()
      var data = JSON.stringify({ session: auth_session, username: auth_username, newpassword: newpassword })
      $.post("/api/update", data, main_userUpdateSuccess, 'json').fail(main_reqError)
      $("#changepw-modal").modal('hide');
    });
    $("#changepw-btn").text("Change");
    $("#changepw-password").keypress(function(event) { overrideEnter(event, $("#changepw-btn")); });
    $("#changepw-password-retype").keypress(function(event) { overrideEnter(event, $("#changepw-btn")); });
    $("#changepw-modal").modal('show');
  });
}


/*
 *
 * Main: global
 *
 */
function async_load(src) {
  var first, s;
  s = document.createElement('script');
  s.src = src;
  s.type = 'text/javascript';
  s.async = true;
  first = document.getElementsByTagName('script')[0];
  return first.parentNode.insertBefore(s, first);
}

function getDateTimeString(d) {
  var datetimestr = Number(d.getDate()).pad(2);
  datetimestr += '.' + Number(d.getMonth() + 1).pad(2);
  datetimestr += '.' + d.getFullYear();
  datetimestr += ' ' + Number(d.getHours()).pad(2);
  datetimestr += ':' + Number(d.getMinutes()).pad(2);
  datetimestr += ':' + Number(d.getSeconds()).pad(2);
  return datetimestr
}

function overrideEnter(event, btn) {
  if(event.which == 13 || event.keyCode == 13) {
    event.preventDefault();
    if(typeof btn !== 'undefined' && btn.prop('disabled') == false) {
      btn.click();
    }
  }
}

function main_reqError(req, status, error) {
  var data = JSON.parse(req.responseText);
  var message = status + ': ';
  if (data.error != "") {
    message += data.error;
  } else {
    message += error;
  }

  if(req.status == 401) {
    var user = auth_username;
    auth_logout();
    $("#login-username").val(user);
    $("#login-password").focus();
    alertbox.error('login-box', "Authentication failure", message);
  } else {
    alertbox.error('mainwindow', "API Error", message);
  }
}

function main_cleanupPasswordModal() {
  $('#changepw-password').parent().attr('class', 'form-group');
  $("#changepw-password").val('');
  $("#changepw-password").trigger('input');
  $("#changepw-password").focus();
  $("#changepw-password-retype").parent().attr('class', 'form-group');
  $("#changepw-password-retype").val('')
  $("#changepw-modal .alertbox").text('');
  $("#changepw-btn").off('click');
  $("#changepw-btn").prop('disabled', true);
}

function main_comparePasswords() {
  if($("#changepw-password").val() == "" || $("#changepw-password").val() != $("#changepw-password-retype").val()) {
    $('#changepw-password-retype').parent().attr('class', 'form-group has-error');
    $("#changepw-btn").prop('disabled', true);
  } else {
    $('#changepw-password-retype').parent().attr('class', 'form-group has-success');
    $("#changepw-btn").prop('disabled', false);
  }
}

var main_PWStrength = new Array(5);
main_PWStrength[0] = 'very weak';
main_PWStrength[1] = 'weak';
main_PWStrength[2] = 'so-so';
main_PWStrength[3] = 'strong';
main_PWStrength[4] = 'very strong';

var main_PWStrengthLevel = new Array(5);
main_PWStrengthLevel[0] = 'danger';
main_PWStrengthLevel[1] = 'danger';
main_PWStrengthLevel[2] = 'warning';
main_PWStrengthLevel[3] = 'success';
main_PWStrengthLevel[4] = 'success';

function main_enablePWChecks() {
  $('#changepw-password').on('input', function() {
    main_comparePasswords();

    var res = zxcvbn($(this).val(), [ $('#changepw-userfield').text(), 'whawty' ]);

    $("#pwestimatedcracktime").html('estimated crack-time: <strong>' + res.crack_times_display.offline_slow_hashing_1e4_per_second + '</strong>');

    var ind = $('#pwstrengthindicator').empty();
    for(var i=0; i<4; ++i) {
      if(i < res.score) {
        ind.append('<span class="glyphicon glyphicon-star pwstrengthscore' + res.score + '" aria-hidden="true"></span>');
      } else {
        ind.append('<span class="glyphicon glyphicon-star-empty pwstrengthscore0" aria-hidden="true"></span>');
      }
    }

    var tips = '';
    if($(this).val() == "") {
      tips = '<div class="alert alert-info" role="alert">Please type in a password</div>';
    } else if(res.feedback.warning) {
      tips = '<div class="alert alert-danger" role="alert">' + res.feedback.warning + '</div>';
    } else {
      tips = '<div class="alert alert-' + main_PWStrengthLevel[res.score] + '" role="alert">This is a ' + main_PWStrength[res.score] + ' password</div>';
    }
    res.feedback.suggestions.forEach(function(tip) {
      tips = tips + '<div class="alert alert-info" role="alert">' + tip + '</div>';
    });

    $("#pwstrengthtips").html(tips);
  });

  $('#changepw-password-retype').on('input', main_comparePasswords);
}

function main_init() {
  if (auth_admin == true) {
    $("#admin-view").show();
    $("#user-view").hide();
    main_adminViewInit();
  } else {
    $("#admin-view").hide();
    $("#user-view").show();
    main_userViewInit();
  }
  async_load('js/zxcvbn.js');
}
