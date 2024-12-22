const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const wsPort = 4000;

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',  
  password: '',  
  database: 'kapal_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

app.use(bodyParser.json());

// Secret untuk JWT
const JWT_SECRET = 'your_jwt_secret_key';

// WebSocket Server
const wss = new WebSocket.Server({ port: wsPort });
wss.on('connection', ws => {
  ws.on('message', message => {
    console.log('received: %s', message);
  });
});

function notifyClients(message) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Register User
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err, result) => {
    if (err) {
      return res.status(500).send('Error registering user');
    }
    res.status(201).send('User registered');
  });
});

// Login User
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).send('Invalid username or password');
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid username or password');
    }

    const token = jwt.sign({ id_user: user.id_user, role: user.role }, JWT_SECRET);
    res.json({ token });
  });
});

// Middleware untuk autentikasi
function authenticate(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) {
    return res.status(401).send('Access denied');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send('Invalid token');
    }
    req.user = decoded;
    next();
  });
}

// CRUD Kapal
// Mendapatkan daftar kapal
app.get('/kapal', authenticate, (req, res) => {
  db.query('SELECT * FROM kapal', (err, results) => {
    if (err) {
      return res.status(500).send('Error fetching kapal data');
    }
    res.json(results);
  });
});

// Menambah kapal (admin)
app.post('/kapal', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Permission denied');
  }

  const { nama_kapal, jenis_kapal, kapasitas_muatan } = req.body;
  db.query('INSERT INTO kapal (nama_kapal, jenis_kapal, kapasitas_muatan) VALUES (?, ?, ?)', [nama_kapal, jenis_kapal, kapasitas_muatan], (err, result) => {
    if (err) {
      return res.status(500).send('Error adding kapal');
    }
    notifyClients({
      event: 'data_changed',
      message: 'Data kapal telah diperbarui.',
      data: [{
        id_kapal: result.insertId,
        nama_kapal,
        jenis_kapal,
        kapasitas_muatan,
        waktu_terdaftar: new Date().toISOString()
      }]
    });
    res.status(201).send('Kapal added');
  });
});

// Mengupdate kapal (admin)
app.put('/kapal/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Permission denied');
  }

  const { id } = req.params;
  const { nama_kapal, jenis_kapal, kapasitas_muatan } = req.body;
  db.query('UPDATE kapal SET nama_kapal = ?, jenis_kapal = ?, kapasitas_muatan = ? WHERE id_kapal = ?', [nama_kapal, jenis_kapal, kapasitas_muatan, id], (err, result) => {
    if (err) {
      return res.status(500).send('Error updating kapal');
    }
    notifyClients({
      event: 'data_changed',
      message: 'Data kapal telah diperbarui.',
      data: [{
        id_kapal: id,
        nama_kapal,
        jenis_kapal,
        kapasitas_muatan,
        waktu_terdaftar: new Date().toISOString()
      }]
    });
    res.status(200).send('Kapal updated');
  });
});

// Menghapus kapal (admin)
app.delete('/kapal/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Permission denied');
  }

  const { id } = req.params;
  db.query('DELETE FROM kapal WHERE id_kapal = ?', [id], (err, result) => {
    if (err) {
      return res.status(500).send('Error deleting kapal');
    }
    notifyClients({
      event: 'data_changed',
      message: 'Data kapal telah diperbarui.',
      data: [{
        id_kapal: id
      }]
    });
    res.status(200).send('Kapal deleted');
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});