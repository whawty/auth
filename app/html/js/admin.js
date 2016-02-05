'use strict';

function admin_init() {
  auth_init()
  main_enablePWStrength();
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
var auth_session = null;

function auth_loginSuccess(data) {
   if (data.session) {
     auth_username = data.username;
     auth_admin = data.admin;
     auth_session = data.session;

     sessionStorage.setItem("auth_username", auth_username);
     sessionStorage.setItem("auth_admin", (auth_admin) ? "true" : "false");
     sessionStorage.setItem("auth_session", auth_session);

     $('#username-field').text(auth_username);
     if (auth_admin == true) {
       $('#role-field').text("Admin");
     } else {
       $('#role-field').text("User");
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
  $('#username-field').text('');
  $('#role-field').text('');
  $('#loginbox').slideDown();
}

function auth_init() {
  auth_username = sessionStorage.getItem("auth_username");
  auth_admin = (sessionStorage.getItem("auth_admin") == "true") ? true : false;
  auth_session = sessionStorage.getItem("auth_session");

  if(auth_session && auth_username) {
    $("#loginbox").hide();
    $('#username-field').text(auth_username);
    if (auth_admin == true) {
      $('#role-field').text("Admin");
    } else {
      $('#role-field').text("User");
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
 * Main: admin view
 *
 */

function main_updateSuccess(data) {
  alertbox.success('mainwindow', "Password Update", "successfully updated password for " + data.username);
  main_updateUserlist()
}

function getUpdateButton(user) {
  var btn = $('<button>').addClass("btn").addClass("btn-primary").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-pencil" aria-hidden="true"></span>&nbsp;&nbsp;Update Password')
  return btn.click(function() {
      main_cleanupPasswordModal()

      $('#changepw-userfield').text(user);
      $("#changepwform").submit(function(event) {
          event.preventDefault();
          var newpassword = $("#newpassword").val()
          if (newpassword != $("#newpassword-retype").val()) {
              alertbox.error('passwordModal', "Error", "Passwords mismatch");
              $("#newpassword").val('')
              $("#newpassword-retype").val('')
              return
          }
          var data = JSON.stringify({ session: auth_session, username: user, newpassword: newpassword })
          $.post("/api/update", data, main_updateSuccess, 'json')
              .fail(main_reqError)
          $("#passwordModal").modal('hide');
      });
      $("#passwordModal").modal('show');
  });
}

function main_removeSuccess(data) {
  alertbox.success('mainwindow', "Remove User", "successfully removed user " + data.username);
  main_updateUserlist()
}

function getRemoveButton(user) {
  var btn = $('<button>').addClass("btn").addClass("btn-danger").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-trash" aria-hidden="true"></span>&nbsp;&nbsp;Remove')
  return btn.click(function() {
      var data = JSON.stringify({ session: auth_session, username: user })
      $.post("/api/remove", data, main_removeSuccess, 'json')
          .fail(main_reqError)
  });
}

function main_setadminSuccess(data) {
  main_updateUserlist()
}

function getSetAdminButton(user, oldstate) {
  var btn = $('<button>').addClass("btn").addClass("btn-warning").addClass("btn-sm")
  btn.html('<span class="glyphicon glyphicon-random" aria-hidden="true"></span>&nbsp;&nbsp;Change Role')
  var newstate = !oldstate;
  return btn.click(function() {
      var data = JSON.stringify({ session: auth_session, username: user, admin: newstate })
      $.post("/api/set-admin", data, main_setadminSuccess, 'json')
          .fail(main_reqError)
  });
}

function getRoleLabel(admin) {
  if (admin == true) {
    return $('<span>').addClass("label").addClass("label-primary").text("Admin")
  } else {
    return $('<span>').addClass("label").addClass("label-default").text("User")
  }
}

function getBoolIcon(flag) {
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
  var datetimestr = Number(lastchange.getDate()).pad(2);
  datetimestr += '.' + Number(lastchange.getMonth() + 1).pad(2);
  datetimestr += '.' + lastchange.getFullYear();
  datetimestr += ' ' + Number(lastchange.getHours()).pad(2);
  datetimestr += ':' + Number(lastchange.getMinutes()).pad(2);
  datetimestr += ':' + Number(lastchange.getSeconds()).pad(2);

  return $('<string>').addClass("last-change").text(datetimestr)
}

function main_userlistSuccess(data) {
  $('#user-list tbody').find('tr').remove();
  for (var user in data.list) {
    var row = $('<tr>').append($('<td>').text(user))
        .append($('<td>').addClass("text-center").append(getRoleLabel(data.list[user].admin)))
        .append($('<td>').append(getLastChange(new Date())))
        .append($('<td>').addClass("text-center").append(getBoolIcon(data.list[user].valid)))
        .append($('<td>').addClass("text-center").append(getBoolIcon(data.list[user].supported)))
        .append($('<td>').text(data.list[user].formatid))
        .append($('<td>').text(data.list[user].formatparams))
        .append($('<td>').addClass("text-center").append(getSetAdminButton(user, data.list[user].admin))
                                                 .append(getUpdateButton(user))
                                                 .append(getRemoveButton(user)));
    $('#user-list > tbody:last').append(row);
  }
}

function main_addSuccess(data) {
  alertbox.success('mainwindow', "Add User", "successfully added user " + data.username);
  main_updateUserlist()
}

function main_setupAddButton() {
  $("#adduserform").submit(function(event) {
      event.preventDefault();
      var user = $("#addusername").val()
      var admin = false
      if ( $('input[name="addrole"]:checked').val()  == "admin") {
        admin = true;
      }
      main_cleanupPasswordModal()

      $('#changepw-userfield').text(user);
      $("#changepwform").submit(function(event) {
          event.preventDefault();
          var newpassword = $("#newpassword").val()
          if (newpassword != $("#newpassword-retype").val()) {
              alertbox.error('passwordModal', "Error", "Passwords mismatch");
              $("#newpassword").val('')
              $("#newpassword-retype").val('')
              return
          }
          var data = JSON.stringify({ session: auth_session, username: user, password: newpassword, admin: admin })
          $.post("/api/add", data, main_addSuccess, 'json')
              .fail(main_reqError)
          $("#passwordModal").modal('hide');
      });
      $("#passwordModal").modal('show');
  });
}

function main_updateUserlist() {
  var data = JSON.stringify({ session: auth_session, })
  $.post("/api/list-full", data, main_userlistSuccess, 'json')
          .fail(main_reqError)
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
  alertbox.success('mainwindow', "Password Update", "successfully updated password for " + data.username);
}

function main_userViewInit() {
  $("#user-view .username").text(auth_username);

  $('#user-view .btn').click(function() {
      main_cleanupPasswordModal()

      $('#changepw-userfield').text(auth_username);
      $("#changepwform").submit(function(event) {
          event.preventDefault();
          var newpassword = $("#newpassword").val()
          if (newpassword != $("#newpassword-retype").val()) {
              alertbox.error('passwordModal', "Error", "Passwords mismatch");
              $("#newpassword").val('')
              $("#newpassword-retype").val('')
              return
          }
          var data = JSON.stringify({ session: auth_session, username: auth_username, newpassword: newpassword })
          $.post("/api/update", data, main_userUpdateSuccess, 'json')
              .fail(main_reqError)
          $("#passwordModal").modal('hide');
      });
      $("#passwordModal").modal('show');
  });

}

/*
 *
 * Main: global
 *
 */

function main_reqError(req, status, error) {
  var data = JSON.parse(req.responseText);
  var message = status + ': ';
  if (data.error != "") {
    message += data.error;
  } else {
    message += error;
  }

  if(req.status == 401) {
    var user = auth_username
    auth_logout();
    $("#username").val(user);
    $("#password").focus();
    alertbox.error('loginbox', "Authentication failure", message);
  } else {
    alertbox.error('mainwindow', "API Error", message);
  }
}

function main_cleanupPasswordModal() {
  $("#newpassword").val('')
  $("#newpassword").trigger('keyup')
  $("#newpassword-retype").val('')
  $('#passwordModal .alertbox').text('');
  $("#changepwform").off("submit");
}

function main_enablePWStrength() {
  $('#newpassword').pwstrength({
    common: {
      minChar: 8,
      usernameField: '#changepw-userfield',
      debug: true,
    },
    rules: {
      activated: {
        wordTwoCharacterClasses: true,
        wordRepetitions: true,
      },
      scores: {
        wordSimilarToUsername: -500,
        wordRepetitions: -100,
      }
    },
    ui: {
      showVerdicts: false,
      showVerdictsInsideProgressBar: false,
    }
  });
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
}
