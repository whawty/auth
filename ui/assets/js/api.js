// Client for the whawty.auth web-api.
//
// The web interface is always served at <base-path>/admin/ and the web-api
// at <base-path>/api/, so the web-api is addressed relative to the page.
// This keeps the web interface working below any path prefix.

const apiBase = new URL('../api/', document.baseURI);

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status; // HTTP status code, 0 if the server was not reachable
  }
}

let unauthorizedHandler = null;

// onUnauthorized registers a function which gets called with the ApiError
// whenever the web-api rejects the session, i.e. because it timed out.
export function onUnauthorized(handler) {
  unauthorizedHandler = handler;
}

async function call(endpoint, payload, { withSession = true } = {}) {
  let response;
  try {
    response = await fetch(new URL(endpoint, apiBase), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'The server is not reachable. Check your network connection and try again.');
  }

  // Errors from a reverse proxy (502, 504, ...) are usually HTML pages.
  let data = null;
  if ((response.headers.get('Content-Type') || '').includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const status = [response.status, response.statusText].filter(Boolean).join(' '); // HTTP/2 has no status text
    const message = (data && data.error) || `The server answered with an unexpected error (${status}).`;
    const err = new ApiError(response.status, message);
    if (response.status === 401 && withSession && unauthorizedHandler) {
      unauthorizedHandler(err);
    }
    throw err;
  }
  if (data === null) {
    throw new ApiError(response.status, 'The server sent a response that is not valid JSON.');
  }
  return data;
}

// authenticate checks username and password and returns
// { session, username, admin, lastchanged }.
export async function authenticate(username, password) {
  const data = await call('authenticate', { username, password }, { withSession: false });
  if (!data.session) {
    throw new ApiError(200, data.error || 'The server did not create a session.');
  }
  return { session: data.session, username: data.username, admin: data.admin, lastchanged: new Date(data.lastchanged) };
}

// listUsers returns all users of the store (admins only) as an object
// mapping usernames to { admin, lastchanged, valid, supported, formatid, paramid }.
export async function listUsers(session) {
  const data = await call('list-full', { session });
  const users = {};
  for (const [name, user] of Object.entries(data.list || {})) {
    users[name] = { ...user, lastchanged: new Date(user.lastchanged) };
  }
  return users;
}

export function addUser(session, username, password, admin) {
  return call('add', { session, username, password, admin });
}

export function removeUser(session, username) {
  return call('remove', { session, username });
}

export function setPassword(session, username, newpassword) {
  return call('update', { session, username, newpassword });
}

export function setAdmin(session, username, admin) {
  return call('set-admin', { session, username, admin });
}
