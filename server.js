const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const upload = multer({ dest: 'uploads/' });
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const SECRET = 'SUPER_SECRET_KEY';
const db = new sqlite3.Database(path.resolve(__dirname, 'pagevente.db'));

// --- Email Transporter ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// --- DB INIT ---
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    price REAL,
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
    comment TEXT
  )`);

  // Table pour tokens de réinitialisation
  db.run(`CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT,
    expires_at INTEGER
  )`);

  db.get(`SELECT * FROM users WHERE username=?`, ['admin734'], (err, row) => {
    if (!row) {
      const hash2 = bcrypt.hashSync('zerotwo27', 10);
      db.run(`INSERT INTO users (username,email,password,is_admin) VALUES (?,?,?,1)`,
        ['admin734', 'admin734@test.com', hash2]);
      console.log('✅ Admin ajouté : admin734 / zerotwo27');
    }
  });
});

// --- Middleware Auth ---
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Pas autorisé' });
  const token = auth.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// --- AUTH ---
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username,email,password) VALUES (?,?,?)`,
    [username, email, hash],
    function (err) {
      if (err) return res.status(400).json({ error: 'Utilisateur déjà existant' });

      // Envoi de l'e-mail de bienvenue
      const mailOptions = {
        from: process.env.MAIL_USER,
        to: email,
        subject: 'Bienvenue sur notre site ! 🎉',
        text: `Bonjour ${username},\n\nMerci de vous être inscrit sur notre site. Nous sommes ravis de vous accueillir !\n\nÀ bientôt,\nL'équipe`
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) console.error('Erreur envoi email :', error);
      });

      const token = jwt.sign({ id: this.lastID, username, is_admin: 0 }, SECRET);
      res.json({ token });
    });
});

app.post('/api/login', (req, res) => {
  const { email, username, password } = req.body;
  const field = email ? 'email' : 'username';
  const value = email || username;
  db.get(`SELECT * FROM users WHERE ${field}=?`, [value], async (err, row) => {
    if (!row) return res.status(400).json({ error: 'Utilisateur non trouvé' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: 'Mot de passe incorrect' });
    const token = jwt.sign({ id: row.id, username: row.username, is_admin: row.is_admin }, SECRET);
    res.json({ token });
  });
});

// --- FORGOT PASSWORD ---
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  db.get(`SELECT * FROM users WHERE email=?`, [email], (err, user) => {
    if (!user) return res.status(400).json({ error: 'Email inconnu' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 1000 * 60 * 30; // 30 min

    db.run(`INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?,?,?)`,
      [user.id, token, expiresAt], (err) => {
        if (err) return res.status(500).json({ error: 'Erreur serveur' });

        const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;

        const mailOptions = {
          from: process.env.MAIL_USER,
          to: email,
          subject: 'Réinitialisation de votre mot de passe 🔒',
          html: `
            <p>Bonjour ${user.username},</p>
            <p>Vous avez demandé à réinitialiser votre mot de passe.</p>
            <p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :</p>
            <a href="${resetLink}">${resetLink}</a>
            <p>Ce lien expirera dans 30 minutes.</p>
          `
        };

        transporter.sendMail(mailOptions, (error) => {
          if (error) {
            console.error('Erreur envoi email :', error);
            return res.status(500).json({ error: 'Erreur envoi email' });
          }
          res.json({ success: true, message: 'Email de réinitialisation envoyé' });
        });
      });
  });
});

// --- RESET PASSWORD ---
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  db.get(`SELECT * FROM reset_tokens WHERE token=?`, [token], async (err, row) => {
    if (!row) return res.status(400).json({ error: 'Lien invalide' });
    if (Date.now() > row.expires_at) {
      db.run(`DELETE FROM reset_tokens WHERE token=?`, [token]);
      return res.status(400).json({ error: 'Lien expiré' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password=? WHERE id=?`, [hash, row.user_id], (err) => {
      if (err) return res.status(500).json({ error: 'Erreur DB' });

      db.run(`DELETE FROM reset_tokens WHERE token=?`, [token]);

      db.get(`SELECT username,is_admin FROM users WHERE id=?`, [row.user_id], (err, user) => {
        const jwtToken = jwt.sign({ id: row.user_id, username: user.username, is_admin: user.is_admin }, SECRET);
        res.json({ success: true, token: jwtToken });
      });
    });
  });
});

// --- PRODUCTS ---
// GET ALL
app.get('/api/products', (req, res) => {
  db.all(`SELECT * FROM products`, [], (err, rows) => {
    res.json(rows);
  });
});

// POST (CREATE)
app.post(
  '/api/products',
  authMiddleware,
  upload.fields([{ name: 'image' }, { name: 'document' }]),
  (req, res) => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
    const { title, price, description } = req.body;
    const image = req.files?.image?.[0]?.path || '';
    const document = req.files?.document?.[0]?.path || '';
    db.run(
      `INSERT INTO products (title,price,description,image,document) VALUES (?,?,?,?,?)`,
      [title, price, description, image, document],
      function (err) {
        if (err) return res.status(500).json({ error: 'Erreur DB' });
        res.json({ id: this.lastID });
      }
    );
  }
);

// PUT (UPDATE)
app.put(
  '/api/products/:id',
  authMiddleware,
  upload.fields([{ name: 'image' }, { name: 'document' }]),
  (req, res) => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
    const { id } = req.params;
    const { title, price, description } = req.body;
    const image = req.files?.image?.[0]?.path;
    const document = req.files?.document?.[0]?.path;

    // Build dynamic query
    let fields = [];
    let values = [];
    if (title) { fields.push('title=?'); values.push(title); }
    if (price) { fields.push('price=?'); values.push(price); }
    if (description) { fields.push('description=?'); values.push(description); }
    if (image) { fields.push('image=?'); values.push(image); }
    if (document) { fields.push('document=?'); values.push(document); }
    values.push(id);

    db.run(`UPDATE products SET ${fields.join(', ')} WHERE id=?`, values, function(err) {
      if (err) return res.status(500).json({ error: 'Erreur DB' });
      if (this.changes === 0) return res.status(404).json({ error: 'Produit introuvable' });
      res.json({ success: true });
    });
  }
);

// DELETE
app.delete('/api/products/:id', authMiddleware, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Accès refusé' });
  const { id } = req.params;
  db.run('DELETE FROM products WHERE id=?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'Erreur DB' });
    if (this.changes === 0) return res.status(404).json({ error: 'Produit introuvable' });
    res.json({ success: true });
  });
});

// --- CART ---
app.post('/api/cart/add', authMiddleware, (req, res) => {
  const { product_id, qty } = req.body;
  const userId = req.user.id;
  db.get('SELECT qty FROM carts WHERE user_id=? AND product_id=?', [userId, product_id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Erreur DB' });

    if (row) {
      const newQty = row.qty + (qty || 1);
      db.run('UPDATE carts SET qty=? WHERE user_id=? AND product_id=?', [newQty, userId, product_id], (err) => {
        if (err) return res.status(500).json({ error: 'Erreur DB' });
        res.json({ success: true });
      });
    } else {
      db.run('INSERT INTO carts (user_id, product_id, qty) VALUES (?,?,?)', [userId, product_id, qty || 1], (err) => {
        if (err) return res.status(500).json({ error: 'Erreur DB' });
        res.json({ success: true });
      });
    }
  });
});

app.post('/api/cart/remove', authMiddleware, (req, res) => {
  const { product_id } = req.body;
  const userId = req.user.id;
  db.run(`DELETE FROM carts WHERE user_id=? AND product_id=?`, [userId, product_id], function (err) {
    if (err) return res.status(500).json({ error: 'Erreur DB' });
    res.json({ success: true });
  });
});

app.get('/api/cart', authMiddleware, (req, res) => {
  const userId = req.user.id;
  db.all(
    `SELECT c.product_id as id, p.title, p.price, p.image, c.qty
     FROM carts c JOIN products p ON p.id=c.product_id
     WHERE c.user_id=?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Erreur DB' });
      res.json(rows);
    }
  );
});

// --- FAVORITES ---
app.post('/api/favorites/toggle', authMiddleware, (req, res) => {
  const { product_id } = req.body;
  const userId = req.user.id;
  db.get(`SELECT * FROM favorites WHERE user_id=? AND product_id=?`, [userId, product_id], (err, row) => {
    if (row) {
      db.run(`DELETE FROM favorites WHERE user_id=? AND product_id=?`, [userId, product_id], function () {
        res.json({ success: true, action: 'removed' });
      });
    } else {
      db.run(`INSERT INTO favorites (user_id, product_id) VALUES (?,?)`, [userId, product_id], function () {
        res.json({ success: true, action: 'added' });
      });
    }
  });
});

app.get('/api/favorites', authMiddleware, (req, res) => {
  const userId = req.user.id;
  db.all(
    `SELECT f.product_id as id, p.title, p.price, p.image
     FROM favorites f JOIN products p ON p.id=f.product_id
     WHERE f.user_id=?`,
    [userId],
    (err, rows) => {
      res.json(rows);
    }
  );
});

// --- REVIEWS ---
app.post('/api/reviews', authMiddleware, (req, res) => {
  const { product_id, rating, comment } = req.body;
  db.get(`SELECT username FROM users WHERE id=?`, [req.user.id], (err, row) => {
    db.run(
      `INSERT INTO reviews (product_id,user_id,username,rating,comment)
       VALUES (?,?,?,?,?)`,
      [product_id, req.user.id, row.username, rating, comment],
      function (err) {
        if (err) return res.status(500).json({ error: 'Erreur DB' });
        res.json({ success: true });
      }
    );
  });
});

app.get('/api/reviews/:product_id', (req, res) => {
  const { product_id } = req.params;
  db.all(`SELECT * FROM reviews WHERE product_id=?`, [product_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erreur DB' });
    res.json(rows);
  });
});

// --- FORGOT PASSWORD (simulé) ---
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  db.get(`SELECT * FROM users WHERE email=?`, [email], (err, row) => {
    if (!row) return res.status(400).json({ error: 'Email inconnu' });
    res.json({ success: true, message: 'Email de réinitialisation envoyé (simulé)' });
  });
});

// --- START SERVER ---
app.listen(3000, () => {
  console.log('✅ Serveur démarré sur http://localhost:3000');
});
