DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS project;
DROP TABLE IF EXISTS logger;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  firstname TEXT NOT NULL,
  lastname TEXT NOT NULL,
  password TEXT NOT NULL,
  project INTEGER,
  role TEXT NOT NULL,
  verified INTEGER
);

CREATE TABLE project (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  description TEXT UNIQUE NOT NULL,
  init DATE NOT NULL,
  end DATE NOT NULL,
  status INTEGER NOT NULL
);

CREATE TABLE logger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  date TEXT NOT NULL,
  user TEXT NOT NULL
);