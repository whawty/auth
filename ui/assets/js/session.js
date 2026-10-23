// Login state of the web interface.
//
// The state is kept in sessionStorage, so it survives reloading the page but
// not closing the tab. sessionStorage is shared by all apps published on the
// same origin, so the keys are prefixed with the app name and its base path.
// The keys are the same as those of the previous web interface.

const prefix = 'whawty-auth:' + new URL('../', document.baseURI).pathname + ':';
const fields = ['username', 'admin', 'lastchanged', 'session'];

// sessionStorage throws in some situations (i.e. blocked site data); the web
// interface then still works, the login is just not kept across reloads.
function read(name) {
  try {
    return sessionStorage.getItem(prefix + name);
  } catch {
    return null;
  }
}

function write(name, value) {
  try {
    sessionStorage.setItem(prefix + name, value);
  } catch {
    // ignore, see above
  }
}

// load returns { username, admin, lastchanged, session } or null if nobody
// is logged in.
export function load() {
  const username = read('username');
  const session = read('session');
  if (!username || !session) {
    return null;
  }
  return {
    username,
    admin: read('admin') === 'true',
    lastchanged: new Date(read('lastchanged')),
    session,
  };
}

export function save({ username, admin, lastchanged, session }) {
  write('username', username);
  write('admin', admin ? 'true' : 'false');
  write('lastchanged', lastchanged.toISOString());
  write('session', session);
}

export function clear() {
  for (const name of fields) {
    try {
      sessionStorage.removeItem(prefix + name);
    } catch {
      // ignore, see above
    }
  }
}
