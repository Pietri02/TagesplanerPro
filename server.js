const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'dein-super-geheimer-schluessel-aendere-mich';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Datenbankdateien
const USERS_FILE = path.join(__dirname, 'users.json');
const TASKS_FILE = path.join(__dirname, 'tasks.json');

// Hilfsfunktionen für Datei-IO
function readJSON(file) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify([]));
    return [];
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Middleware zur Token-Verifizierung
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Kein Token vorhanden' });
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Ungültiger Token' });
    req.user = user;
    next();
  });
}

// ROUTEN

// Registrierung
app.post('/api/register', async (req, res) => {
  const { username, email, password, fullName } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
  }
  
  const users = readJSON(USERS_FILE);
  
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Benutzername existiert bereits' });
  }
  
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'E-Mail existiert bereits' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  const newUser = {
    id: Date.now().toString(),
    username,
    email,
    password: hashedPassword,
    fullName: fullName || username,
    createdAt: new Date().toISOString()
  };
  
  users.push(newUser);
  writeJSON(USERS_FILE, users);
  
  res.status(201).json({ message: 'Benutzer erfolgreich erstellt', userId: newUser.id });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username === username);
  
  if (!user) {
    return res.status(400).json({ error: 'Benutzer nicht gefunden' });
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  
  if (!validPassword) {
    return res.status(400).json({ error: 'Falsches Passwort' });
  }
  
  const token = jwt.sign(
    { id: user.id, username: user.username },
    SECRET_KEY,
    { expiresIn: '7d' }
  );
  
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName
    }
  });
});

// Benutzerprofil abrufen
app.get('/api/profile', authenticateToken, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  
  if (!user) {
    return res.status(404).json({ error: 'Benutzer nicht gefunden' });
  }
  
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName
  });
});

// Alle Benutzer abrufen (für Teilen-Funktion)
app.get('/api/users', authenticateToken, (req, res) => {
  const users = readJSON(USERS_FILE);
  const userList = users.map(u => ({
    id: u.id,
    username: u.username,
    fullName: u.fullName
  }));
  res.json(userList);
});

// Tasks abrufen
app.get('/api/tasks', authenticateToken, (req, res) => {
  const tasks = readJSON(TASKS_FILE);
  const userTasks = tasks.filter(t => 
    t.owner === req.user.id || 
    (t.sharedWith && t.sharedWith.includes(req.user.id))
  );
  res.json(userTasks);
});

// Task erstellen
app.post('/api/tasks', authenticateToken, (req, res) => {
  const tasks = readJSON(TASKS_FILE);
  
  const newTask = {
    id: Date.now().toString(),
    ...req.body,
    owner: req.user.id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    history: [{
      action: 'created',
      timestamp: new Date().toISOString(),
      user: req.user.username
    }]
  };
  
  tasks.push(newTask);
  writeJSON(TASKS_FILE, tasks);
  
  res.status(201).json(newTask);
});

// Task aktualisieren
app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const tasks = readJSON(TASKS_FILE);
  const taskIndex = tasks.findIndex(t => t.id === req.params.id);
  
  if (taskIndex === -1) {
    return res.status(404).json({ error: 'Task nicht gefunden' });
  }
  
  const task = tasks[taskIndex];
  
  if (task.owner !== req.user.id && 
      (!task.sharedWith || !task.sharedWith.includes(req.user.id))) {
    return res.status(403).json({ error: 'Keine Berechtigung' });
  }
  
  const updatedTask = {
    ...task,
    ...req.body,
    id: task.id,
    owner: task.owner,
    updatedAt: new Date().toISOString(),
    history: [
      ...task.history,
      {
        action: 'updated',
        timestamp: new Date().toISOString(),
        user: req.user.username,
        changes: req.body
      }
    ]
  };
  
  tasks[taskIndex] = updatedTask;
  writeJSON(TASKS_FILE, tasks);
  
  res.json(updatedTask);
});

// Task löschen
app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
  const tasks = readJSON(TASKS_FILE);
  const taskIndex = tasks.findIndex(t => t.id === req.params.id);
  
  if (taskIndex === -1) {
    return res.status(404).json({ error: 'Task nicht gefunden' });
  }
  
  const task = tasks[taskIndex];
  
  if (task.owner !== req.user.id) {
    return res.status(403).json({ error: 'Keine Berechtigung' });
  }
  
  tasks.splice(taskIndex, 1);
  writeJSON(TASKS_FILE, tasks);
  
  res.json({ message: 'Task gelöscht' });
});

// Statistiken abrufen
app.get('/api/stats', authenticateToken, (req, res) => {
  const tasks = readJSON(TASKS_FILE);
  const userTasks = tasks.filter(t => t.owner === req.user.id);
  
  const stats = {
    total: userTasks.length,
    completed: userTasks.filter(t => t.status === 'completed').length,
    pending: userTasks.filter(t => t.status === 'open').length,
    waiting: userTasks.filter(t => t.status === 'waiting').length,
    byCategory: {},
    byPriority: {
      low: userTasks.filter(t => t.priority === 'low').length,
      normal: userTasks.filter(t => t.priority === 'normal').length,
      high: userTasks.filter(t => t.priority === 'high').length
    },
    completionRate: userTasks.length > 0 
      ? Math.round((userTasks.filter(t => t.status === 'completed').length / userTasks.length) * 100)
      : 0
  };
  
  // Kategorien zählen
  userTasks.forEach(task => {
    if (task.category) {
      stats.byCategory[task.category] = (stats.byCategory[task.category] || 0) + 1;
    }
  });
  
  res.json(stats);
});

app.listen(PORT, () => {
  console.log(`✅ Server läuft auf http://localhost:${PORT}`);
  console.log(`📂 Öffne deinen Browser und gehe zu: http://localhost:${PORT}`);
});
