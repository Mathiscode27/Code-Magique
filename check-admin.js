const db = require('./db');

db.get('SELECT username, email, password, is_admin FROM users WHERE username = ?', ['admin734'], (err, row) => {
  if (err) {
    console.error('Erreur:', err);
    process.exit(1);
  }
  
  console.log('Utilisateur trouvé:', row);
  process.exit(0);
});