const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const root = path.resolve(__dirname);
const port = process.env.PORT || 3000;
const dataPath = path.join(__dirname, 'data.json');

// Charger les données utilisateurs
let data = { users: [] };
try {
  data = JSON.parse(fs.readFileSync(dataPath));
} catch (e) {
  console.error('Erreur de chargement data.json:', e);
}

// Générer un token JWT simple
function generateToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: user.is_admin
  })).toString('base64url');
  const signature = crypto
    .createHmac('sha256', 'votre-secret-key')
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

const mime = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
};

const server = http.createServer(async (req, res) => {
  // Activer CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  // Gérer les API
  if (req.url.startsWith('/api/')) {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      return req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          
          // API Login
          if (req.url === '/api/login') {
            const user = data.users.find(u => 
              (payload.email && u.email === payload.email) || 
              (payload.username && u.username === payload.username)
            );
            
            if (user && user.password === payload.password) {
              const token = generateToken(user);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ token }));
            }
            
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Identifiants invalides' }));
          }
          
          // API Register
          if (req.url === '/api/register') {
            const existingUser = data.users.find(u => 
              u.email === payload.email || 
              u.username === payload.username
            );
            
            if (existingUser) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ error: 'Utilisateur déjà existant' }));
            }
            
            const newUser = {
              id: data.users.length + 1,
              username: payload.username,
              email: payload.email,
              password: payload.password,
              is_admin: false
            };
            
            data.users.push(newUser);
            fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
            
            const token = generateToken(newUser);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ token }));
          }
        } catch (e) {
          console.error('Erreur API:', e);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Erreur serveur' }));
        }
      });
    }
    
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'API non trouvée' }));
  }

  // Servir les fichiers statiques
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.join(root, urlPath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, {'Content-Type':'text/plain'});
      return res.end('Not found');
    }
    const ext = path.extname(filePath).toLowerCase();
    const type = mime[ext] || 'application/octet-stream';
    res.writeHead(200, {'Content-Type': type});
    res.end(data);
  });
});

server.listen(port, () => console.log(`Static server running at http://localhost:${port} serving ${root}`));
process.on('uncaughtException', e => console.error(e));
process.on('SIGINT', () => { server.close(); process.exit(); });