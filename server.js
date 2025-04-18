const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Enable CORS
app.use(cors());
app.use(express.json());

// Secret key for JWT
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Store connected clients
const clients = new Set();
// Store users
const users = new Map();

// Helper function to generate JWT token
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
}

// Middleware to verify JWT token
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// WebSocket connection handling
wss.on('connection', (ws) => {
  let user = null;
  clients.add(ws);

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received message:', data);

      switch (data.type) {
        case 'login':
          try {
            const decoded = jwt.verify(data.token, JWT_SECRET);
            user = decoded;
            broadcastToAll({
              type: 'system',
              content: `${user.username} has joined the chat`
            });
          } catch (error) {
            console.error('Login error:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Invalid token'
            }));
          }
          break;

        case 'message':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }

          const messageData = {
            type: 'message',
            content: data.content,
            sender: user.username,
            timestamp: new Date().toISOString()
          };

          console.log('Broadcasting message:', messageData);
          broadcastToAll(messageData);
          break;
      }
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({
        type: 'error',
        content: 'Error processing message'
      }));
    }
  });

  ws.on('close', () => {
    if (user) {
      broadcastToAll({
        type: 'system',
        content: `${user.username} has left the chat`
      });
    }
    clients.delete(ws);
  });
});

function broadcastToAll(message) {
  console.log('Broadcasting message:', message);
  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// REST endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (users.has(username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now().toString(),
      username,
      password: hashedPassword
    };

    users.set(username, newUser);
    res.json({ message: 'Registration successful' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.get(username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    res.json({
      token,
      user: {
        username: user.username
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 