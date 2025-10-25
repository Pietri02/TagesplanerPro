const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'dein-super-geheimer-schluessel-aendere-mich';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/taskmaster';

// Models
const User = require('./models/User');
const Task = require('./models/Task');

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// MongoDB Verbindung
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB verbunden!'))
  .catch(err => console.error('❌ MongoDB Fehler:', err));

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
  
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ error: 'Benutzername existiert bereits' });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ error: 'E-Mail existiert bereits' });
      }
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      fullName: fullName || username
    });
    
    await newUser.save();
    
    res.status(201).json({ message: 'Benutzer erfolgreich erstellt', userId: newUser._id });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(400).json({ error: 'Benutzer nicht gefunden' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(400).json({ error: 'Falsches Passwort' });
    }
    
    const token = jwt.sign(
      { id: user._id.toString(), username: user.username },
      SECRET_KEY,
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Benutzerprofil abrufen
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    }
    
    res.json({
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      fullName: user.fullName
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Alle Benutzer abrufen
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select('username fullName');
    const userList = users.map(u => ({
      id: u._id.toString(),
      username: u.username,
      fullName: u.fullName
    }));
    res.json(userList);
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Tasks abrufen
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({
      $or: [
        { owner: req.user.id },
        { sharedWith: req.user.id }
      ]
    });
    
    const tasksWithStringId = tasks.map(task => ({
      ...task.toObject(),
      id: task._id.toString()
    }));
    
    res.json(tasksWithStringId);
  } catch (error) {
    console.error('Tasks error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Task erstellen
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const newTask = new Task({
      ...req.body,
      owner: req.user.id,
      history: [{
        action: 'created',
        timestamp: new Date(),
        user: req.user.username
      }]
    });
    
    await newTask.save();
    
    res.status(201).json({
      ...newTask.toObject(),
      id: newTask._id.toString()
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Task aktualisieren
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    
    if (!task) {
      return res.status(404).json({ error: 'Task nicht gefunden' });
    }
    
    if (task.owner !== req.user.id && !task.sharedWith.includes(req.user.id)) {
      return res.status(403).json({ error: 'Keine Berechtigung' });
    }
    
    const historyEntry = {
      action: 'updated',
      timestamp: new Date(),
      user: req.user.username,
      changes: req.body
    };
    
    Object.assign(task, req.body);
    task.updatedAt = new Date();
    task.history.push(historyEntry);
    
    await task.save();
    
    res.json({
      ...task.toObject(),
      id: task._id.toString()
    });
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Task löschen
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    
    if (!task) {
      return res.status(404).json({ error: 'Task nicht gefunden' });
    }
    
    if (task.owner !== req.user.id) {
      return res.status(403).json({ error: 'Keine Berechtigung' });
    }
    
    await Task.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Task gelöscht' });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Statistiken
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({ owner: req.user.id });
    
    const stats = {
      total: tasks.length,
      completed: tasks.filter(t => t.status === 'completed').length,
      pending: tasks.filter(t => t.status === 'open').length,
      waiting: tasks.filter(t => t.status === 'waiting').length,
      byCategory: {},
      byPriority: {
        low: tasks.filter(t => t.priority === 'low').length,
        normal: tasks.filter(t => t.priority === 'normal').length,
        high: tasks.filter(t => t.priority === 'high').length
      },
      completionRate: tasks.length > 0 
        ? Math.round((tasks.filter(t => t.status === 'completed').length / tasks.length) * 100)
        : 0
    };
    
    tasks.forEach(task => {
      if (task.category) {
        stats.byCategory[task.category] = (stats.byCategory[task.category] || 0) + 1;
      }
    });
    
    res.json(stats);
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server läuft auf Port ${PORT}`);
});
