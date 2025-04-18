require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://ankitsuperku:kdTeeHosKEl1HSLw@cluster0.5melvxj.mongodb.net/chat_app?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  type: { type: String, required: true },
  content: { type: String, required: true },
  sender: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Enable CORS
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-secure-refresh-secret-key';

// In-memory storage for active sessions
const clients = new Map(); // Store WebSocket connections
const blacklistedTokens = new Set(); // Store invalidated tokens
const userSessions = new Map(); // Store user sessions
const refreshTokens = new Map();

// Password complexity requirements
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Helper function to generate JWT tokens
function generateTokens(user) {
  const accessToken = jwt.sign(
    { id: user._id, username: user.username },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { id: user._id, username: user.username },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

// Middleware to verify JWT token
function verifyToken(token) {
  if (blacklistedTokens.has(token)) {
    return null;
  }
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Function to broadcast online users count
function broadcastOnlineUsers() {
  const onlineUsers = Array.from(new Set(Array.from(userSessions.keys())));
  console.log('Broadcasting unique online users:', onlineUsers);
  const message = {
    type: 'onlineUsers',
    users: onlineUsers,
    count: onlineUsers.length
  };
  broadcastToAll(message);
}

// WebSocket connection handling
wss.on('connection', (ws) => {
  let user = null;
  let sessionId = null;

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received message:', data);

      switch (data.type) {
        case 'login':
          try {
            const decoded = verifyToken(data.token);
            if (!decoded) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Invalid or expired token'
              }));
              return;
            }
            user = decoded;
            sessionId = Date.now().toString();
            clients.set(ws, { user, sessionId });
            userSessions.set(user.username, { sessionId, lastActive: Date.now() });
            
            // Send chat history
            try {
              console.log('Loading chat history for user:', user.username);
              const history = await Message.find()
                .sort({ timestamp: 1 }) // Sort by ascending order
                .lean();
              
              console.log('Found messages in database:', history.length);
              
              // Format messages for client
              const formattedHistory = history.map(msg => ({
                type: msg.type,
                content: msg.content,
                sender: msg.sender,
                timestamp: new Date(msg.timestamp).toISOString()
              }));

              console.log('Sending formatted history:', formattedHistory.length, 'messages');
              ws.send(JSON.stringify({
                type: 'history',
                messages: formattedHistory
              }));
            } catch (error) {
              console.error('Error loading chat history:', error);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Error loading chat history'
              }));
            }

            broadcastOnlineUsers();
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
            timestamp: new Date()
          };

          // Store message in MongoDB
          try {
            const newMessage = new Message(messageData);
            await newMessage.save();
            console.log('Message saved to database:', messageData);
          } catch (error) {
            console.error('Error saving message:', error);
          }

          // Format message for broadcasting
          const broadcastMessage = {
            ...messageData,
            timestamp: messageData.timestamp.toISOString()
          };

          broadcastToAll(broadcastMessage);
          break;

        case 'logout':
          if (user) {
            blacklistedTokens.add(data.token);
            userSessions.delete(user.username);
            broadcastToAll({
              type: 'system',
              content: `${user.username} has left the chat`
            });
            clients.delete(ws);
            user = null;
            sessionId = null;
            
            broadcastOnlineUsers();
          }
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
      userSessions.delete(user.username);
      broadcastToAll({
        type: 'system',
        content: `${user.username} has left the chat`
      });
      clients.delete(ws);
      
      broadcastOnlineUsers();
    }
  });
});

function broadcastToAll(message) {
  console.log('Broadcasting message:', message);
  clients.forEach((clientInfo, client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// Input validation middleware
const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('password')
    .matches(passwordRegex)
    .withMessage('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

const validateLogin = [
  body('username').notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
];

// REST endpoints
app.post('/api/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, isAdmin } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      isAdmin: isAdmin || false
    });

    await newUser.save();
    res.json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user);
    refreshTokens.set(refreshToken, user.username);

    userSessions.set(username, {
      sessionId: Date.now().toString(),
      lastActive: Date.now()
    });

    res.json({
      accessToken,
      refreshToken,
      user: {
        username: user.username,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Add the logout endpoint
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    const username = refreshTokens.get(refreshToken);
    if (username) {
      // Find associated access token to blacklist (optional but good practice)
      // This requires storing the access token associated with the refresh token
      // For simplicity, we'll just remove the refresh token for now.
      refreshTokens.delete(refreshToken);
      console.log(`User ${username} logged out, refresh token invalidated.`);
    }
    // It's often useful to blacklist the current access token as well
    // You might need to send the access token in the logout request body or headers
    // if (req.headers.authorization) {
    //   const token = req.headers.authorization.split(' ')[1];
    //   blacklistedTokens.add(token);
    // }
  }
  res.json({ message: 'Logout successful' });
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 