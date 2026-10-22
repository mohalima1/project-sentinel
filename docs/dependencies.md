# Dependency compatibility

Verified development environment: Python 3.12.13 on Windows x64, Node 24.22.0,
npm 11.19.1, and uv 0.11.24. Direct application/test dependencies use exact versions
in pyproject.toml and frontend/package.json. Transitive runtime dependencies are
recorded in uv.lock and package-lock.json. Install using locked sync and npm ci.

Official documentation consulted during implementation:

- [FastAPI](https://fastapi.tiangolo.com/): JSON endpoints, request validation,
  dependencies, and lifespan initialization. Installed FastAPI 0.159.1.
- [SQLAlchemy SQLite dialect](https://docs.sqlalchemy.org/en/20/dialects/sqlite.html):
  Python 3.12 explicit transaction control and foreign-key pragma handling.
  Installed SQLAlchemy 2.0.55; the project enables autocommit=False and temporarily
  enables autocommit to configure foreign keys on each connection.
- [Alembic tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html):
  explicit migrations and revision management. Installed Alembic 1.20.1.
- [React](https://react.dev/learn/creating-a-react-app): a custom client application
  suits the existing FastAPI API boundary. Installed React/React DOM 19.3.1.
- [Vite guide](https://vite.dev/guide/): supported Node versions and React TypeScript
  integration. Node 24.22.0 meets its 22.12+ requirement. Vite 8.3.5,
  plugin-react 6.1.2, and TypeScript 7.0.2 compile the actual application successfully.

The resolved Starlette TestClient source recommends httpx2; httpx2 2.16.0 is pinned
for tests. The earlier httpx dependency produced a deprecation warning and was
replaced. Browser tests use Playwright 1.64.1 and its matching Chromium download.

No preferred-stack deviation remains. Service packaging is intentionally deferred
under the user's milestone instruction. Hosted GitHub Actions have been added but
not executed on GitHub; local equivalent commands were executed and recorded.
