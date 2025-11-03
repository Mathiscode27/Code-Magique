const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const DB_PATH = path.resolve(__dirname, 'pagevente.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Erreur ouverture DB :', err.message);
  } else {
    console.log('✅ Base de données SQLite ouverte :', DB_PATH);
  }
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    image TEXT,
    document TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS carts (
    user_id INTEGER,
    product_id INTEGER,
    qty INTEGER,
    PRIMARY KEY(user_id, product_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER,
    product_id INTEGER,
    PRIMARY KEY(user_id, product_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    user_id INTEGER,
    username TEXT,
    rating INTEGER,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const adminUsername = 'admin734';
  const adminPassword = 'zerotwo27';
  const adminEmail = 'admin@pagevente.local';

  db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, row) => {
    if (err) return console.error('❌ Erreur vérification admin :', err.message);
    if (!row) {
      bcrypt.hash(adminPassword, 10)
        .then(hash => {
          db.run(
            'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 1)',
            [adminUsername, adminEmail, hash],
            (err) => {
              if (err) {
                console.error('❌ Erreur création admin :', err.message);
              } else {
                console.log('✅ Admin créé : username=admin734 password=zerotwo27');
              }
            }
          );
        })
        .catch(err => console.error('❌ Erreur hash admin :', err.message));
    } else {
      console.log('ℹ️ Admin déjà présent dans la base.');
    }
  });
});

module.exports = db;
