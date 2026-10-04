# Orbit Examination Portal

The project includes a static overview page and an interactive exam application, backed by a Node.js API and SQLite database.

## Run locally

Requirements: Node.js 22.13 or newer.

1. Install dependencies with `npm install`.
2. Copy `.env.example` to `.env` and set `JWT_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`. Use a random secret of at least 32 characters and an administrator password of at least 12 characters.
3. Start the app with `npm start`.
4. Open `http://localhost:3000`. The API health check is at `http://localhost:3000/api/health`.
5. Run the API tests with `npm test`.

The administrator is created from environment settings the first time the database is initialized. Student accounts are created through registration. Passwords are hashed; exam answers and grading are handled by the server.

## Hosting

GitHub Pages serves static files only; it cannot run this Node.js API. The Node service can serve both HTML pages and the API from one host. For a separate API host, set `window.ORBIT_API_URL` before the Babel script in `app.html` to that host's `/api` URL and add the GitHub Pages origin to `ALLOWED_ORIGINS`. Sign-in on GitHub Pages reports that the API is unconfigured until this is set.

SQLite data must be stored on persistent storage when deploying to a cloud host. Set `DATABASE_PATH` to a path on the host's persistent disk. Do not commit `.env` or the database file.