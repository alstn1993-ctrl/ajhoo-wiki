-- 실제 스키마는 app.py init()에서 자동 생성됩니다. 아래는 핵심 구조 요약입니다.
CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, passhash TEXT NOT NULL);
CREATE TABLE sessions (tokenhash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id), csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE categories (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, position INTEGER NOT NULL DEFAULT 0);
CREATE TABLE documents (id INTEGER PRIMARY KEY, category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','published')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE revisions (id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, saved_at TEXT NOT NULL);
