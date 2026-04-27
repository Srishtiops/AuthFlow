# AuthFlow

AuthFlow is a Flask-based authentication and monitoring application with a React/Tailwind frontend bundle.

## Features

- Flask backend with session management
- User and admin dashboards
- File upload and access controls
- Monitoring and risk evaluation logic
- Frontend assets bundled from `frontend/react` and `frontend/styles`

## Setup

### 1. Install backend dependencies

Make sure you have Python installed, then install required packages:

```powershell
pip install flask werkzeug
```

### 2. Install frontend dependencies

```powershell
npm install
```

### 3. Build frontend assets

```powershell
npm run build
```

This generates:

- `static/css/theme.css`
- `static/js/theme-react.js`

## Run the app

Start the Flask server:

```powershell
python app.py
```

By default it runs on `http://0.0.0.0:5000`.

## Project structure

- `app.py` - Flask application entrypoint
- `database.py` - user/session/file management helpers
- `monitor.py` - risk and security monitoring logic
- `risk_engine.py` - risk evaluation utilities
- `frontend/react` - React widget source
- `frontend/styles` - Tailwind CSS source
- `static` - built frontend assets and static files
- `templates` - Flask HTML templates
- `users.json` - user data store

## Notes

- Keep the `users.json` and `shared_files` directories accessible to the app.
- Add any additional Python dependencies to the install step as needed.
