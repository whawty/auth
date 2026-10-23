// Login state of the web interface.
//
// The state is kept in sessionStorage, so it survives reloading the page but
// not closing the tab. sessionStorage is shared by all apps published on the
// same origin, so the key contains the app name and its base path.

const key = 'whawty-auth:' + new URL('../', document.baseURI).pathname + ':login';

// sessionStorage throws in some situations (i.e. blocked site data); the web
// interface then still works, the login is just not kept across reloads.
function storage(action) {
  try {
    return action(sessionStorage);
  } catch {
    return null;
  }
}

// load returns { username, admin, lastchanged, session } or null if nobody
// is logged in.
export function load() {
  const raw = storage((s) => s.getItem(key));
  if (!raw) {
    return null;
  }
  try {
    const state = JSON.parse(raw);
    if (typeof state.username !== 'string' || !state.username || typeof state.session !== 'string' || !state.session) {
      throw new Error('incomplete login state');
    }
    return {
      username: state.username,
      admin: state.admin === true,
      lastchanged: new Date(state.lastchanged),
      session: state.session,
    };
  } catch {
    clear();
    return null;
  }
}

export function save({ username, admin, lastchanged, session }) {
  const state = { username, admin, lastchanged: lastchanged.toISOString(), session };
  storage((s) => s.setItem(key, JSON.stringify(state)));
}

export function clear() {
  storage((s) => s.removeItem(key));
}
