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
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Cloudinary storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'chat_attachments',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'],
    resource_type: 'auto'
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

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
  createdAt: { type: Date, default: Date.now },
  avatar: { type: String, default: null },
  contacts: [{ type: String }] // List of usernames in contacts
});

const chatSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true, 
    enum: ['group', 'direct'] 
  },
  name: { 
    type: String, 
    required: function() { return this.type === 'group'; }  
  },
  participants: [{ type: String }], // List of usernames
  createdBy: { type: String },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  lastActivity: { type: Date, default: Date.now },
  avatar: { type: String, default: null }
});

const messageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  type: { type: String, required: true, enum: ['text', 'file', 'image', 'edited', 'deleted'] },
  content: { type: String, required: true },
  sender: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  readBy: [{ type: String }], // List of usernames who have read this message
  deletedFor: [{ type: String }], // List of usernames who have deleted this message
  fileUrl: { type: String }, // URL for file attachments
  fileName: { type: String }, // Original file name
  fileSize: { type: Number }, // File size in bytes
  fileType: { type: String }, // MIME type of the file
  editHistory: [{ // Track message edits
    content: { type: String, required: true },
    editedAt: { type: Date, default: Date.now }
  }],
  isEdited: { type: Boolean, default: false },
  editedAt: { type: Date },
  isDeleted: { type: Boolean, default: false },
  deletedAt: { type: Date }
});

// Add indexes for better query performance
messageSchema.index({ chatId: 1, timestamp: -1 });
messageSchema.index({ sender: 1, timestamp: -1 });
messageSchema.index({ readBy: 1 });

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

// Add after MongoDB Schemas
const chatRooms = new Map(); // Store active chat rooms

// Enable CORS
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 requests per windowMs for auth endpoints
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per windowMs for general endpoints
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to specific routes instead of globally
app.use('/api/login', authLimiter);
app.use('/api/refresh-token', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/', apiLimiter); // For all other API routes

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-secure-refresh-secret-key';

// In-memory storage for active sessions
const clients = new Map(); // Store WebSocket connections
const blacklistedTokens = new Set(); // Store invalidated tokens
const userSessions = new Map(); // Store user sessions
const refreshTokens = new Map();

// Heartbeat interval (30 seconds)
const HEARTBEAT_INTERVAL = 30000;
const HEARTBEAT_TIMEOUT = 10000;

// Password complexity requirements
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Connection management variables
const connectionPool = new Map(); // username -> array of ws connections
const userLastSeen = new Map(); // username -> timestamp
const isUserConnecting = new Map(); // username -> timestamp (throttle reconnections)
const broadcastTimers = new Map(); // Store timers for throttled broadcasts
const systemMessageHistory = new Map(); // Track recent system messages

// Maximum WebSocket message size
const MAX_MESSAGE_SIZE = 1024 * 50; // 50KB

// Constants for connection management
const CONNECTION_TIMEOUT_MS = 60000; // 60 seconds
const CONNECTION_CHECK_INTERVAL = 30000; // 30 seconds
const BROADCAST_THROTTLE_MS = 5000; // 5 seconds
const SYSTEM_MESSAGE_THROTTLE_MS = 15000; // 15 seconds
const CLEANUP_INTERVAL = 60000; // 1 minute

// Add typing status tracking
const typingUsers = new Map(); // chatId -> Set of typing users
const typingTimeouts = new Map(); // username_chatId -> timeout

// Function to broadcast typing status
function broadcastTypingStatus(chatId, username, isTyping) {
  Chat.findById(chatId).then(chat => {
    if (!chat) return;

    const message = {
      type: 'typing_status',
      chatId,
      username,
      isTyping
    };

    // Broadcast to all participants except the sender
    chat.participants.forEach(participant => {
      if (participant !== username) {
        const userConnections = Array.from(clients.entries())
          .filter(([_, client]) => client.user?.username === participant);

        userConnections.forEach(([ws]) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message));
          }
        });
      }
    });
  }).catch(error => {
    console.error('Error broadcasting typing status:', error);
  });
}

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
  
  // Broadcast to ALL clients (including those not logged in)
  console.log(`Broadcasting online users to ${clients.size} clients`);
  const sentUsers = new Set(); // Track who we've sent to already
  
  clients.forEach((clientInfo, client) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        // Only send one notification per unique username
        const username = clientInfo.user?.username || 'anonymous';
        if (!sentUsers.has(username)) {
          client.send(JSON.stringify(message));
          sentUsers.add(username);
          console.log(`Sent online users to ${username}`);
        }
      } catch (error) {
        console.error(`Error sending online users to ${clientInfo.user?.username || 'anonymous'}:`, error);
      }
    }
  });
}

// This is a throttle helper to prevent excessive broadcasts
let broadcastThrottleTimeout = null;
let lastBroadcastTime = 0;
const BROADCAST_THROTTLE_INTERVAL = 5000; // 5 seconds between broadcasts

function throttledBroadcastOnlineUsers() {
  const now = Date.now();
  if (now - lastBroadcastTime < BROADCAST_THROTTLE_INTERVAL) {
    // If we broadcast too recently, schedule a delayed broadcast
    if (!broadcastThrottleTimeout) {
      broadcastThrottleTimeout = setTimeout(() => {
        broadcastOnlineUsers();
        lastBroadcastTime = Date.now();
        broadcastThrottleTimeout = null;
      }, BROADCAST_THROTTLE_INTERVAL - (now - lastBroadcastTime));
    }
  } else {
    // If enough time has passed, broadcast immediately
    broadcastOnlineUsers();
    lastBroadcastTime = now;
  }
}

// Keep track of system messages to avoid spamming
const systemMessages = new Map(); // username -> { lastMessage, count, lastTime }

function throttledSystemMessage(username, type, joining = true) {
  const now = Date.now();
  const messageKey = `${username}-${joining ? 'join' : 'leave'}`;
  const lastMessage = systemMessages.get(messageKey);
  
  // If we've sent this message recently, don't send it again
  if (lastMessage && now - lastMessage.time < 10000) {
    return;
  }
  
  // Update the last message time
  systemMessages.set(messageKey, { time: now });
  
  // Only send if we're actually broadcasting
  const message = {
    type: 'system',
    content: `${username} has ${joining ? 'joined' : 'left'} the chat`
  };
  
  broadcastToAll(message);
}

// Helper function to ensure ID is a string
function ensureStringId(id) {
  if (!id) return null;
  return id.toString ? id.toString() : id;
}

// Function to ping all clients periodically to keep connections alive
function startHeartbeat() {
  setInterval(() => {
    console.log(`Sending heartbeat to ${clients.size} clients`);
    clients.forEach((clientInfo, ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        // Set a timeout to terminate the connection if no pong is received
        const terminationTimeout = setTimeout(() => {
          console.log(`Client ${clientInfo.user?.username || 'unknown'} failed to respond to heartbeat, terminating connection`);
          try {
            ws.terminate();
          } catch (error) {
            console.error('Error terminating connection:', error);
          }
        }, HEARTBEAT_TIMEOUT);
        
        // Store the timeout ID so we can clear it when pong is received
        clientInfo.terminationTimeout = terminationTimeout;
        
        // Send ping
        try {
          ws.ping();
        } catch (error) {
          console.error('Error sending ping:', error);
          clearTimeout(terminationTimeout);
          ws.terminate();
        }
      } else if (ws.readyState !== WebSocket.CONNECTING) {
        // If not open or connecting, remove from clients map
        clients.delete(ws);
        
        // If this client had a user, update userSessions
        if (clientInfo.user) {
          const username = clientInfo.user.username;
          let otherConnectionsExist = false;
          
          // Check if user has other active connections
          clients.forEach((info) => {
            if (info.user && info.user.username === username) {
              otherConnectionsExist = true;
            }
          });
          
          // If no other connections exist, remove from userSessions
          if (!otherConnectionsExist) {
            userSessions.delete(username);
            throttledBroadcastOnlineUsers(); // Broadcast updated online users list
          }
        }
      }
    });
    
    // Broadcast online users with each heartbeat to ensure everyone has the latest list
    // But do it less frequently to avoid flooding
    throttledBroadcastOnlineUsers();
  }, HEARTBEAT_INTERVAL);
}

// Start the heartbeat when server starts
startHeartbeat();

// WebSocket connection handling
wss.on('connection', (ws) => {
  let user = null;
  let sessionId = null;
  
  // Track this connection with status info
  ws.isAuthenticated = false;
  ws.connectionTime = Date.now();
  ws.lastActivity = Date.now();
  
  // Initial client entry without user information
  clients.set(ws, { 
    user: null, 
    sessionId: null,
    connectionTime: ws.connectionTime
  });
  
  // Handle pong response
  ws.on('pong', () => {
    const clientInfo = clients.get(ws);
    if (clientInfo && clientInfo.terminationTimeout) {
      clearTimeout(clientInfo.terminationTimeout);
      clientInfo.terminationTimeout = null;
      
      // Update last active timestamp
      ws.lastActivity = Date.now();
      if (clientInfo.user) {
        const sessionInfo = userSessions.get(clientInfo.user.username);
        if (sessionInfo) {
          sessionInfo.lastActive = Date.now();
          userSessions.set(clientInfo.user.username, sessionInfo);
        }
      }
      
      clients.set(ws, clientInfo); // Update client info
    }
  });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received message:', data);
      ws.lastActivity = Date.now();

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
            
            // If this user was already logged in with this connection, don't double-process
            if (user && user.username === decoded.username && ws.isAuthenticated) {
              console.log(`User ${decoded.username} already logged in on this connection`);
              return;
            }
            
            const username = decoded.username;
            
            // Check for existing connections for this user and handle them
            let disconnectedOldConnection = false;
            let activeConnectionsCount = 0;
            
            clients.forEach((clientInfo, clientWs) => {
              if (clientWs !== ws && 
                  clientInfo.user && 
                  clientInfo.user.username === username) {
                
                activeConnectionsCount++;
                
                // If this is a stale connection (inactive for more than 30 seconds), close it
                const inactivityTime = Date.now() - (clientWs.lastActivity || clientInfo.connectionTime);
                if (inactivityTime > 30000) { // 30 seconds of inactivity
                  console.log(`Closing stale connection for ${username}, inactive for ${inactivityTime}ms`);
                  clientWs.close(1000, "Replaced by newer connection");
                  disconnectedOldConnection = true;
                }
              }
            });
            
            console.log(`User ${username} has ${activeConnectionsCount} other active connections`);
            
            // Mark the current connection as authenticated
            ws.isAuthenticated = true;
            user = decoded;
            sessionId = Date.now().toString();
            
            // Update client info in clients map
            clients.set(ws, { 
              user, 
              sessionId, 
              connectionTime: ws.connectionTime, 
              lastActivity: Date.now() 
            });
            
            // Update userSessions
            userSessions.set(username, { 
              sessionId, 
              lastActive: Date.now(),
              userId: user.id,
              connectionCount: activeConnectionsCount + 1
            });
            
            // Only send joining message if this is the first connection or we closed a stale one
            if (activeConnectionsCount === 0 || disconnectedOldConnection) {
              throttledSystemMessage(username, 'system', true);
            }
            
            // Always update online users list, but throttled
            throttledBroadcastOnlineUsers();
            
            // Send user's chats list
            try {
              console.log('Loading chats for user:', username);
              const chats = await Chat.find({
                participants: username
              }).sort({ lastActivity: -1 }).lean();
              
              // Get last message for each chat
              const chatsWithLastMessage = await Promise.all(chats.map(async (chat) => {
                const lastMessage = await Message.findOne({ chatId: chat._id })
                  .sort({ timestamp: -1 })
                  .limit(1)
                  .lean();
                
                // Get other participants for display purposes
                const otherParticipants = chat.participants.filter(p => p !== username);
                
                // Count unread messages for this user
                const unreadCount = await Message.countDocuments({
                  chatId: chat._id,
                  sender: { $ne: username },
                  readBy: { $ne: username }
                });
                
                // Ensure _id is a string for frontend
                const chatWithStringId = {
                  ...chat,
                  _id: ensureStringId(chat._id),
                  lastMessage: lastMessage ? {
                    ...lastMessage,
                    _id: ensureStringId(lastMessage._id),
                    chatId: ensureStringId(lastMessage.chatId),
                  } : null,
                  otherParticipants,
                  unreadCount
                };
                
                return chatWithStringId;
              }));
              
              console.log('Sending chats list:', chatsWithLastMessage.length, 'chats');
              ws.send(JSON.stringify({
                type: 'chats',
                chats: chatsWithLastMessage
              }));
            } catch (error) {
              console.error('Error loading chats:', error);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Error loading chats'
              }));
            }
            
            // Send list of available users
            try {
              const availableUsers = await User.find({ username: { $ne: username } })
                .select('username avatar')
                .lean();
                
              ws.send(JSON.stringify({
                type: 'users',
                users: availableUsers
              }));
            } catch (error) {
              console.error('Error loading users:', error);
            }
          } catch (error) {
            console.error('Login error:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Invalid token'
            }));
          }
          break;
          
        case 'chat_message':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }

          try {
            const { chatId, content, fileUrl, fileName, fileSize, fileType } = data;
            
            if (!chatId || !content) {
              console.error('Missing chatId or content:', data);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Missing chatId or message content'
              }));
              return;
            }
            
            // Check if user is part of this chat
            let chat = await Chat.findById(chatId);
            
            // If chat doesn't exist, create a new DM chat
            if (!chat) {
              // Try to find existing DM chat with these participants
              const otherUser = content.startsWith('@') ? content.split(' ')[0].substring(1) : null;
              if (otherUser) {
                chat = await Chat.findOne({
                  type: 'direct',
                  participants: { $all: [user.username, otherUser], $size: 2 }
                });
              }
              
              // If still no chat, create new one
              if (!chat && otherUser) {
                // Verify other user exists
                const otherUserExists = await User.findOne({ username: otherUser });
                if (!otherUserExists) {
                  ws.send(JSON.stringify({
                    type: 'error',
                    content: 'User not found'
                  }));
                  return;
                }
                
                chat = new Chat({
                  type: 'direct',
                  participants: [user.username, otherUser],
                  name: `${user.username}_${otherUser}`,
                  createdBy: user.username
                });
                
                await chat.save();
                
                // Notify the other user about the new chat
                const otherUserConnections = Array.from(clients.entries())
                  .filter(([_, client]) => client.user?.username === otherUser);
                
                otherUserConnections.forEach(([clientWs]) => {
                  if (clientWs.readyState === WebSocket.OPEN) {
                    clientWs.send(JSON.stringify({
                      type: 'new_chat',
                      chat: {
                        ...chat.toObject(),
                        _id: chat._id.toString(),
                        lastMessage: null
                      }
                    }));
                  }
                });
              }
            }

            if (!chat) {
              console.error('Chat not found and could not be created');
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }
            
            // Check if user is a participant or add them if it's a DM
            if (!chat.participants.includes(user.username)) {
              if (chat.type === 'direct') {
                chat.participants.push(user.username);
                await chat.save();
              } else {
                console.error('User not in chat participants:', user.username, chat.participants);
                ws.send(JSON.stringify({
                  type: 'error',
                  content: 'You are not a participant in this chat'
                }));
                return;
              }
            }
            
            // Create and save the message
            const messageData = {
              chatId: chat._id,
              type: fileUrl ? 'file' : 'text',
              content,
              sender: user.username,
              timestamp: new Date(),
              readBy: [user.username],
              fileUrl,
              fileName,
              fileSize,
              fileType
            };

            // Store message in MongoDB
            try {
              const newMessage = new Message(messageData);
              await newMessage.save();
              console.log('Message saved to database:', messageData);
              
              // Update chat's lastActivity
              chat.lastActivity = new Date();
              await chat.save();
              
              // Format message for broadcasting with string IDs
              const broadcastMessage = {
                type: 'chat_message',
                chatId: chat._id.toString(),
                messageData: {
                  ...messageData,
                  _id: newMessage._id.toString(),
                  chatId: messageData.chatId.toString(),
                  timestamp: messageData.timestamp.toISOString()
                }
              };

              // Track which users have received the message
              const messageReceivedBy = new Set();
              
              // Broadcast to all participants
              chat.participants.forEach(participant => {
                const participantConnections = Array.from(clients.entries())
                  .filter(([_, client]) => client.user?.username === participant);
                  
                participantConnections.forEach(([clientWs]) => {
                  if (clientWs.readyState === WebSocket.OPEN && !messageReceivedBy.has(participant)) {
                    clientWs.send(JSON.stringify(broadcastMessage));
                    messageReceivedBy.add(participant);
                    
                    // Send notification if not the sender
                    if (participant !== user.username) {
                      clientWs.send(JSON.stringify({
                        type: 'notification',
                        chatId: chat._id.toString(),
                        sender: user.username,
                        content: content.substring(0, 50) + (content.length > 50 ? '...' : ''),
                        timestamp: new Date().toISOString()
                      }));
                    }
                  }
                });
              });
              
              console.log(`Message broadcast to ${messageReceivedBy.size} unique users`);
            } catch (error) {
              console.error('Error saving message:', error);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Error saving message'
              }));
            }
          } catch (error) {
            console.error('Error processing chat message:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error processing message'
            }));
          }
          break;
          
        case 'join_chat':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }
          
          try {
            const { chatId } = data;
            
            if (!chatId) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Missing chatId'
              }));
              return;
            }
            
            // Check if user is allowed to access this chat
            const chat = await Chat.findById(chatId);
            if (!chat) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }
            
            if (!chat.participants.includes(user.username)) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'You are not a participant in this chat'
              }));
              return;
            }
            
            // Load chat history, excluding deleted messages for this user
            const messages = await Message.find({
              chatId,
              deletedFor: { $ne: user.username }
            })
              .sort({ timestamp: 1 })
              .lean();
              
            // Format messages with string IDs
            const formattedMessages = messages.map(msg => ({
              ...msg,
              _id: ensureStringId(msg._id),
              chatId: ensureStringId(msg.chatId),
              timestamp: new Date(msg.timestamp).toISOString()
            }));
            
            console.log(`Sending chat history for chat ${chatId}: ${formattedMessages.length} messages`);
            
            ws.send(JSON.stringify({
              type: 'chat_history',
              chatId: ensureStringId(chatId),
              messages: formattedMessages
            }));
            
            // Mark messages as read
            if (messages.length > 0) {
              for (const message of messages) {
                if (!message.readBy.includes(user.username)) {
                  await Message.updateOne(
                    { _id: message._id },
                    { $addToSet: { readBy: user.username } }
                  );
                  
                  // Broadcast read status
                  chat.participants.forEach(participant => {
                    const participantConnections = Array.from(clients.entries())
                      .filter(([_, client]) => client.user?.username === participant);
                      
                    participantConnections.forEach(([clientWs]) => {
                      if (clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'message_read',
                          messageId: message._id.toString(),
                          chatId: message.chatId.toString(),
                          username: user.username,
                          readBy: [...message.readBy, user.username]
                        }));
                      }
                    });
                  });
                }
              }
            }
          } catch (error) {
            console.error('Error joining chat:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error loading chat'
            }));
          }
          break;

        case 'create_chat':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }
          
          try {
            const { chatType, name, participants } = data;
            
            if (!chatType || (chatType === 'direct' && !participants?.length) || (chatType === 'group' && !name)) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Missing required chat information'
              }));
              return;
            }
            
            let newChat;
            
            // Handle direct message creation
            if (chatType === 'direct') {
              const otherUser = participants[0];
              
              // Check if user exists
              const userExists = await User.findOne({ username: otherUser });
              if (!userExists) {
                ws.send(JSON.stringify({
                  type: 'error',
                  content: 'User not found'
                }));
                return;
              }
              
              // Check if chat already exists (including deleted ones)
              const existingChat = await Chat.findOne({
                type: 'direct',
                $or: [
                  { participants: { $all: [user.username, otherUser], $size: 2 } },
                  { 
                    name: { 
                      $in: [
                        `${user.username}_${otherUser}`,
                        `${otherUser}_${user.username}`
                      ]
                    }
                  }
                ]
              });
              
              if (existingChat) {
                // If chat exists but user was removed, add them back
                if (!existingChat.participants.includes(user.username)) {
                  existingChat.participants.push(user.username);
                }
                if (!existingChat.participants.includes(otherUser)) {
                  existingChat.participants.push(otherUser);
                }
                existingChat.isActive = true;
                await existingChat.save();
                newChat = existingChat;
              } else {
                // Create new direct chat
                newChat = new Chat({
                  type: 'direct',
                  name: `${user.username}_${otherUser}`,
                  participants: [user.username, otherUser],
                  createdBy: user.username,
                  isActive: true
                });
                
                await newChat.save();
              }
            } 
            // Handle group chat creation
            else if (chatType === 'group') {
              // Ensure creator is in participants
              let allParticipants = Array.isArray(participants) ? [...participants] : [];
              if (!allParticipants.includes(user.username)) {
                allParticipants.push(user.username);
              }
              
              // Create new group
              newChat = new Chat({
                type: 'group',
                name,
                participants: allParticipants,
                createdBy: user.username,
                isActive: true
              });
              
              await newChat.save();
              
              // Notify other participants about the new chat
              for (const participant of allParticipants) {
                if (participant !== user.username) {
                  const participantConnections = Array.from(clients.entries())
                    .filter(([_, client]) => client.user?.username === participant);
                    
                  participantConnections.forEach(([clientWs]) => {
                    if (clientWs.readyState === WebSocket.OPEN) {
                      clientWs.send(JSON.stringify({
                        type: 'new_chat',
                        chat: {
                          ...newChat.toObject(),
                          _id: newChat._id.toString()
                        }
                      }));
                    }
                  });
                }
              }
            }
            
            // Send the new chat to the creator
            ws.send(JSON.stringify({
              type: 'new_chat',
              chat: {
                ...newChat.toObject(),
                _id: newChat._id.toString()
              }
            }));
            
          } catch (error) {
            console.error('Error creating chat:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error creating chat'
            }));
          }
          break;

        case 'logout':
          if (user) {
            blacklistedTokens.add(data.token);
            
            // Get current connection count
            let remainingConnections = 0;
            clients.forEach((info) => {
              if (info.user && info.user.username === user.username && info.user !== ws) {
                remainingConnections++;
              }
            });
            
            // Only remove from sessions if this is the last connection
            if (remainingConnections === 0) {
              userSessions.delete(user.username);
              // Only broadcast departure if actually logged out completely
              throttledSystemMessage(user.username, 'system', false);
            }
            
            // Update online users list
            throttledBroadcastOnlineUsers();
            
            clients.delete(ws);
            ws.isAuthenticated = false;
            user = null;
            sessionId = null;
          }
          break;

        case 'view_members':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }

          try {
            const { chatId } = data;
            const chat = await Chat.findById(chatId);
            
            if (!chat) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }

            if (!chat.participants.includes(user.username)) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'You are not a participant in this chat'
              }));
              return;
            }

            // Get online status for each member
            const members = chat.participants.map(username => ({
              username,
              isOnline: userSessions.has(username)
            }));

            ws.send(JSON.stringify({
              type: 'chat_members',
              chatId: chat._id.toString(),
              members
            }));
          } catch (error) {
            console.error('Error viewing members:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error viewing members'
            }));
          }
          break;

        case 'clear_chat':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }

          try {
            const { chatId } = data;
            const chat = await Chat.findById(chatId);
            
            if (!chat) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }

            if (!chat.participants.includes(user.username)) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'You are not a participant in this chat'
              }));
              return;
            }

            // Clear messages for this user by marking them as deleted for this user
            await Message.updateMany(
              { chatId },
              { $addToSet: { deletedFor: user.username } }
            );

            ws.send(JSON.stringify({
              type: 'chat_cleared',
              chatId: chat._id.toString()
            }));

            // Send empty chat history
            ws.send(JSON.stringify({
              type: 'chat_history',
              chatId: chat._id.toString(),
              messages: []
            }));
          } catch (error) {
            console.error('Error clearing chat:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error clearing chat'
            }));
          }
          break;

        case 'delete_chat':
          if (!user) {
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Please login first'
            }));
            return;
          }

          try {
            const { chatId } = data;
            const chat = await Chat.findById(chatId);
            
            if (!chat) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }

            if (!chat.participants.includes(user.username)) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'You are not a participant in this chat'
              }));
              return;
            }

            // Remove user from participants
            await Chat.findByIdAndUpdate(chatId, {
              $pull: { participants: user.username }
            });

            // Mark all messages as deleted for this user
            await Message.updateMany(
              { chatId },
              { $addToSet: { deletedFor: user.username } }
            );

            ws.send(JSON.stringify({
              type: 'chat_deleted',
              chatId: chat._id.toString()
            }));

            // Update the user's chat list
            const updatedChats = await Chat.find({
              participants: user.username
            }).sort({ lastActivity: -1 }).lean();

            ws.send(JSON.stringify({
              type: 'chats',
              chats: updatedChats
            }));
          } catch (error) {
            console.error('Error deleting chat:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Error deleting chat'
            }));
          }
          break;

        case 'typing_start':
          if (!user || !data.chatId) break;
          
          const chatTypingUsers = typingUsers.get(data.chatId) || new Set();
          chatTypingUsers.add(user.username);
          typingUsers.set(data.chatId, chatTypingUsers);
          
          // Clear existing timeout if any
          const timeoutKey = `${user.username}_${data.chatId}`;
          if (typingTimeouts.has(timeoutKey)) {
            clearTimeout(typingTimeouts.get(timeoutKey));
          }
          
          // Set new timeout
          typingTimeouts.set(timeoutKey, setTimeout(() => {
            const users = typingUsers.get(data.chatId);
            if (users) {
              users.delete(user.username);
              if (users.size === 0) {
                typingUsers.delete(data.chatId);
              }
              broadcastTypingStatus(data.chatId, user.username, false);
            }
            typingTimeouts.delete(timeoutKey);
          }, 3000));
          
          broadcastTypingStatus(data.chatId, user.username, true);
          break;

        case 'typing_stop':
          if (!user || !data.chatId) break;
          
          const typingSet = typingUsers.get(data.chatId);
          if (typingSet) {
            typingSet.delete(user.username);
            if (typingSet.size === 0) {
              typingUsers.delete(data.chatId);
            }
          }
          
          const typingTimeoutKey = `${user.username}_${data.chatId}`;
          if (typingTimeouts.has(typingTimeoutKey)) {
            clearTimeout(typingTimeouts.get(typingTimeoutKey));
            typingTimeouts.delete(typingTimeoutKey);
          }
          
          broadcastTypingStatus(data.chatId, user.username, false);
          break;

        case 'message_read':
          if (!user || !data.messageId) break;
          
          try {
            const message = await Message.findById(data.messageId);
            if (!message) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Message not found'
              }));
              break;
            }
            
            // Add user to readBy array if not already there
            if (!message.readBy.includes(user.username)) {
              message.readBy.push(user.username);
              await message.save();
              
              // Broadcast read status to all participants
              const chat = await Chat.findById(message.chatId);
              if (chat) {
                chat.participants.forEach(participant => {
                  const participantConnections = Array.from(clients.entries())
                    .filter(([_, client]) => client.user?.username === participant);
                    
                  participantConnections.forEach(([clientWs]) => {
                    if (clientWs.readyState === WebSocket.OPEN) {
                      clientWs.send(JSON.stringify({
                        type: 'message_read',
                        messageId: message._id.toString(),
                        chatId: message.chatId.toString(),
                        username: user.username,
                        readBy: message.readBy
                      }));
                    }
                  });
                });
              }
            }
          } catch (error) {
            console.error('Error marking message as read:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Failed to mark message as read'
            }));
          }
          break;

        case 'edit_message':
          if (!user || !data.messageId || !data.content) break;
          
          try {
            const message = await Message.findById(data.messageId);
            if (!message || message.sender !== user.username) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Cannot edit this message'
              }));
              break;
            }

            // Check if message is within 20-minute edit window
            const messageTime = new Date(message.timestamp).getTime();
            const currentTime = new Date().getTime();
            const timeDiff = currentTime - messageTime;
            const EDIT_WINDOW = 20 * 60 * 1000; // 20 minutes in milliseconds

            if (timeDiff > EDIT_WINDOW) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Messages can only be edited within 20 minutes of sending'
              }));
              break;
            }
            
            // Add current content to edit history
            message.editHistory.push({
              content: message.content,
              editedAt: new Date()
            });
            
            // Update message
            message.content = data.content;
            message.isEdited = true;
            message.editedAt = new Date();
            await message.save();
            
            // Get the chat to broadcast to all participants
            const chat = await Chat.findById(message.chatId);
            if (chat) {
              // Broadcast edit to all chat participants
              const editedMessage = {
                type: 'message_edited',
                messageId: message._id.toString(),
                chatId: message.chatId.toString(),
                content: message.content,
                editedAt: message.editedAt.toISOString(),
                editHistory: message.editHistory,
                sender: message.sender,
                timestamp: message.timestamp,
                isEdited: true
              };
              
              chat.participants.forEach(participant => {
                const participantConnections = Array.from(clients.entries())
                  .filter(([_, client]) => client.user?.username === participant);
                  
                participantConnections.forEach(([clientWs]) => {
                  if (clientWs.readyState === WebSocket.OPEN) {
                    clientWs.send(JSON.stringify(editedMessage));
                  }
                });
              });
            }
          } catch (error) {
            console.error('Error editing message:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Failed to edit message'
            }));
          }
          break;

        case 'delete_message':
          if (!user || !data.messageId) break;
          
          try {
            const message = await Message.findById(data.messageId);
            if (!message || message.sender !== user.username) {
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Cannot delete this message'
              }));
              break;
            }
            
            // Instead of just adding to deletedFor, we'll mark the message as deleted
            message.type = 'deleted';
            message.content = 'This message has been deleted';
            message.isDeleted = true;
            message.deletedAt = new Date();
            await message.save();
            
            // Get the chat to broadcast to all participants
            const chat = await Chat.findById(message.chatId);
            if (chat) {
              const deletedMessage = {
                type: 'message_deleted',
                messageId: message._id.toString(),
                chatId: message.chatId.toString(),
                content: message.content,
                deletedAt: message.deletedAt.toISOString(),
                sender: message.sender,
                timestamp: message.timestamp,
                isDeleted: true
              };
              
              chat.participants.forEach(participant => {
                const participantConnections = Array.from(clients.entries())
                  .filter(([_, client]) => client.user?.username === participant);
                  
                participantConnections.forEach(([clientWs]) => {
                  if (clientWs.readyState === WebSocket.OPEN) {
                    clientWs.send(JSON.stringify(deletedMessage));
                  }
                });
              });
            }
          } catch (error) {
            console.error('Error deleting message:', error);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Failed to delete message'
            }));
          }
          break;
      }
    } catch (error) {
      console.error('Error processing message:', error);
      try {
        ws.send(JSON.stringify({
          type: 'error',
          content: 'Error processing message'
        }));
      } catch (sendError) {
        console.error('Error sending error message:', sendError);
      }
    }
  });

  ws.on('close', () => {
    // Get client info before removing
    const clientInfo = clients.get(ws);
    
    // Remove from clients map
    clients.delete(ws);
    
    // If this connection had a user
    if (clientInfo && clientInfo.user) {
      const username = clientInfo.user.username;
      let otherConnectionsExist = false;
      let otherConnectionsCount = 0;
      
      // Check if user has other active connections
      clients.forEach((info) => {
        if (info.user && info.user.username === username) {
          otherConnectionsExist = true;
          otherConnectionsCount++;
        }
      });
      
      console.log(`Connection closed for ${username}, other connections: ${otherConnectionsCount}`);
      
      // Only remove from userSessions if no other connections exist
      if (!otherConnectionsExist) {
        userSessions.delete(username);
        console.log(`User ${username} disconnected. Remaining sessions:`, Array.from(userSessions.keys()));
        
        // Broadcast updated online users, but throttled
        throttledBroadcastOnlineUsers();
        
        // Don't send system message immediately, wait longer to see if they reconnect
        setTimeout(() => {
          // Check again if the user has reconnected
          let reconnected = false;
          clients.forEach((info) => {
            if (info.user && info.user.username === username) {
              reconnected = true;
            }
          });
          
          // Only broadcast system message if they haven't reconnected after a significant delay
          if (!reconnected) {
            throttledSystemMessage(username, 'system', false);
          }
        }, 15000); // Wait 15 seconds before announcing departure
      }
    }
  });

  // Handle errors
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
    // Remove connection on error
    clients.delete(ws);
  });
});

// Enhance the function to broadcast to all
function broadcastToAll(message) {
  console.log('Broadcasting message:', message);
  
  // Rate limiting for system messages
  if (message.type === 'system') {
    const now = Date.now();
    const lastSystemBroadcast = broadcastToAll.lastSystemBroadcast || 0;
    
    // If we've sent a system message too recently, don't send this one
    if (now - lastSystemBroadcast < 5000) { // 5 seconds
      console.log('System message throttled due to recent broadcast');
      return;
    }
    
    broadcastToAll.lastSystemBroadcast = now;
  }
  
  let sentCount = 0;
  const sentToUsers = new Set();
  
  clients.forEach((clientInfo, client) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        // Don't send duplicate messages to the same user across multiple sessions
        const username = clientInfo.user?.username || client.id || 'anonymous';
        if (!sentToUsers.has(username)) {
          client.send(JSON.stringify(message));
          sentToUsers.add(username);
          sentCount++;
        }
      } catch (error) {
        console.error('Error broadcasting message:', error);
      }
    }
  });
  console.log(`Message broadcast to ${sentCount} unique users`);
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

// Update the refresh token endpoint with better error handling
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }
    
    // Verify the refresh token
    const username = refreshTokens.get(refreshToken);
    if (!username) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Find the user
    const user = await User.findOne({ username });
    if (!user) {
      refreshTokens.delete(refreshToken);
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Generate new tokens
    const { accessToken: newAccessToken, refreshToken: newRefreshToken } = generateTokens(user);
    
    // Invalidate old refresh token and store new one
    refreshTokens.delete(refreshToken);
    refreshTokens.set(newRefreshToken, username);
    
    // Update user session
    userSessions.set(username, {
      sessionId: Date.now().toString(),
      lastActive: Date.now(),
      userId: user._id
    });
    
    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user: {
        username: user.username,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
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

// REST endpoints for chats
app.post('/api/chats', async (req, res) => {
  try {
    const { token, type, name, participants } = req.body;
    
    // Verify user is authenticated
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const creator = decoded.username;
    
    // For direct messages, ensure there are exactly 2 participants
    if (type === 'direct') {
      if (!participants || participants.length !== 1) {
        return res.status(400).json({ error: 'Direct chat must have exactly one other participant' });
      }
      
      const otherUser = participants[0];
      
      // Check if the other user exists
      const userExists = await User.findOne({ username: otherUser });
      if (!userExists) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      // Check if a direct chat already exists between these users
      const existingChat = await Chat.findOne({
        type: 'direct',
        participants: { $all: [creator, otherUser], $size: 2 }
      });
      
      if (existingChat) {
        return res.json({ chat: existingChat });
      }
      
      // Create a new direct chat
      const newChat = new Chat({
        type: 'direct',
        participants: [creator, otherUser],
        createdBy: creator,
        name: `${creator}_${otherUser}`
      });
      
      await newChat.save();
      return res.status(201).json({ chat: newChat });
    } 
    // For group chats
    else if (type === 'group') {
      if (!name) {
        return res.status(400).json({ error: 'Group chat requires a name' });
      }
      
      // Ensure creator is included in participants
      let allParticipants = participants || [];
      if (!allParticipants.includes(creator)) {
        allParticipants.push(creator);
      }
      
      // Create new group chat
      const newChat = new Chat({
        type: 'group',
        name,
        participants: allParticipants,
        createdBy: creator
      });
      
      await newChat.save();
      return res.status(201).json({ chat: newChat });
    } else {
      return res.status(400).json({ error: 'Invalid chat type' });
    }
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// Get chats for a user
app.get('/api/chats', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    // Verify user is authenticated
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const username = decoded.username;
    
    // Find all chats where the user is a participant
    const chats = await Chat.find({
      participants: username
    }).sort({ lastActivity: -1 });
    
    // Get the last message for each chat
    const chatsWithLastMessage = await Promise.all(chats.map(async (chat) => {
      const lastMessage = await Message.findOne({ chatId: chat._id })
        .sort({ timestamp: -1 })
        .limit(1);
      
      return {
        ...chat.toObject(),
        lastMessage: lastMessage || null
      };
    }));
    
    res.json({ chats: chatsWithLastMessage });
  } catch (error) {
    console.error('Get chats error:', error);
    res.status(500).json({ error: 'Failed to retrieve chats' });
  }
});

// Get messages for a specific chat
app.get('/api/chats/:chatId/messages', async (req, res) => {
  try {
    const { chatId } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    
    // Verify user is authenticated
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const username = decoded.username;
    
    // Check if user is a participant in this chat
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }
    
    if (!chat.participants.includes(username)) {
      return res.status(403).json({ error: 'Not authorized to access this chat' });
    }
    
    // Get messages for this chat
    const messages = await Message.find({ chatId })
      .sort({ timestamp: 1 });
    
    res.json({ messages });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
});

// Add message to a chat
app.post('/api/chats/:chatId/messages', async (req, res) => {
  try {
    const { chatId } = req.params;
    const { token, content } = req.body;
    
    // Verify user is authenticated
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const username = decoded.username;
    
    // Check if user is a participant in this chat
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }
    
    if (!chat.participants.includes(username)) {
      return res.status(403).json({ error: 'Not authorized to post in this chat' });
    }
    
    // Create new message
    const newMessage = new Message({
      chatId,
      type: 'message',
      content,
      sender: username,
      readBy: [username] // Sender has read their own message
    });
    
    await newMessage.save();
    
    // Update chat's lastActivity time
    chat.lastActivity = new Date();
    await chat.save();
    
    // Broadcast message to all online participants
    broadcastMessageToChat(chat._id, {
      type: 'message',
      chatId: chat._id,
      content,
      sender: username,
      timestamp: newMessage.timestamp.toISOString()
    });
    
    res.status(201).json({ message: newMessage });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Function to broadcast a message to all online participants of a chat
function broadcastMessageToChat(chatId, message) {
  clients.forEach((clientInfo, client) => {
    if (client.readyState === WebSocket.OPEN) {
      // Check if this client's user is a participant in the chat
      Chat.findById(chatId)
        .then(chat => {
          if (chat && chat.participants.includes(clientInfo.user.username)) {
            client.send(JSON.stringify(message));
          }
        })
        .catch(err => console.error('Error checking chat participants:', err));
    }
  });
}

// Get all users (for contacts)
app.get('/api/users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    // Verify user is authenticated
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Get all users except the requesting user
    const users = await User.find({ username: { $ne: decoded.username } })
      .select('username avatar');
    
    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Start heartbeat and cleanup timers
function initializeConnectionManagement() {
  startHeartbeat();
  
  // Clean up stale connections
  setInterval(() => {
    const now = Date.now();
    
    // Check each user's connections
    for (const [username, connections] of connectionPool.entries()) {
      // Filter out dead/closed connections
      const liveConnections = connections.filter(conn => {
        if (!conn || conn.readyState === WebSocket.CLOSED || conn.readyState === WebSocket.CLOSING) {
          return false;
        }
        
        // Check if connection is stale (no pong received for too long)
        if (conn.lastPong && now - conn.lastPong > CONNECTION_TIMEOUT_MS) {
          console.log(`Closing stale connection for ${username} (no pong for ${(now - conn.lastPong)/1000}s)`);
          try {
            conn.terminate();
          } catch (err) {
            console.error(`Error closing stale connection: ${err.message}`);
          }
          return false;
        }
        
        return true;
      });
      
      // Update the connection pool or remove user if no connections remain
      if (liveConnections.length === 0) {
        connectionPool.delete(username);
        
        // Only broadcast a "left" message if user has been gone for a while
        if (userLastSeen.get(username) && now - userLastSeen.get(username) > SYSTEM_MESSAGE_THROTTLE_MS) {
          throttledSystemMessage(username, 'system', false);
        }
      } else {
        connectionPool.set(username, liveConnections);
      }
    }
    
    // Check for unused maps entries
    for (const [username, timestamp] of userLastSeen.entries()) {
      if (!connectionPool.has(username) && now - timestamp > 3600000) { // 1 hour
        userLastSeen.delete(username);
      }
    }
    
    // Clear expired message history
    for (const [key, data] of systemMessageHistory.entries()) {
      if (now - data.timestamp > 3600000) { // 1 hour
        systemMessageHistory.delete(key);
      }
    }
    
    // Clean up broadcast timers
    for (const [key, timer] of broadcastTimers.entries()) {
      if (timer.timestamp && now - timer.timestamp > 60000) { // 1 minute
        clearTimeout(timer.timerId);
        broadcastTimers.delete(key);
      }
    }
    
  }, CLEANUP_INTERVAL);
}

// Connection tracking with health monitoring
const connections = new Map();
const tokenToUsername = new Map();
let pingInterval;

// Start a ping interval to keep connections alive
function startPingInterval() {
  // Clear any existing interval
  if (pingInterval) {
    clearInterval(pingInterval);
  }
  
  pingInterval = setInterval(() => {
    const now = Date.now();
    
    // Send pings to all clients and check for stale connections
    connections.forEach((clientData, client) => {
      try {
        // Check if client hasn't responded in too long
        if (clientData.lastPong && now - clientData.lastPong > 120000) { // 2 minutes
          console.log(`Closing stale connection for ${clientData.username || 'unknown'}`);
          client.terminate();
          return;
        }
        
        // Only send ping if the client hasn't communicated in a while
        if (now - clientData.lastActivity > 30000) { // 30 seconds
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ 
              type: 'ping', 
              timestamp: now 
            }));
            clientData.lastPingSent = now;
          }
        }
      } catch (error) {
        console.error('Error in ping interval for client:', error);
        try {
          client.terminate();
        } catch (e) {
          // Ignore errors when terminating an already closed connection
        }
      }
    });
    
    // Broadcast online users occasionally to keep counts synchronized
    broadcastOnlineUsers();
  }, 30000); // Check every 30 seconds
}

// Start the ping interval
startPingInterval();

// WebSocket connection handler
wss.on('connection', (socket, req) => {
  console.log('New WebSocket connection');
  
  // Initialize client data
  connections.set(socket, {
    authenticated: false,
    username: null,
    userId: null,
    lastActivity: Date.now(),
    lastPingSent: null,
    lastPong: Date.now(),
    sessionStart: Date.now()
  });
  
  // Send a welcome message
  socket.send(JSON.stringify({
    type: 'hello',
    message: 'Connected to chat server'
  }));
  
  // Message handler
  socket.on('message', async (message) => {
    const clientData = connections.get(socket);
    clientData.lastActivity = Date.now();
    
    try {
      const data = JSON.parse(message.toString());
      
      switch (data.type) {
        case 'ping':
          // Client is checking connection
          socket.send(JSON.stringify({ 
            type: 'pong', 
            timestamp: Date.now(),
            received: data.timestamp
          }));
          break;
          
        case 'pong':
          // Client responded to our ping
          clientData.lastPong = Date.now();
          break;
          
        case 'login':
          // Handle authentication
          try {
            if (!data.token) {
              throw new Error('No token provided');
            }
            
            // Verify token
            const decoded = jwt.verify(data.token, JWT_SECRET);
            
            // Check if token is blacklisted
            if (blacklistedTokens.has(data.token)) {
              throw new Error('Token has been invalidated');
            }
            
            // Get user data
            const userSession = userSessions.get(decoded.id);
            if (!userSession) {
              throw new Error('No active session found');
            }
            
            // Update client data
            clientData.authenticated = true;
            clientData.username = decoded.username;
            clientData.userId = decoded.id;
            tokenToUsername.set(data.token, decoded.username);
            
            console.log(`User authenticated: ${decoded.username}`);
            
            // Send success response
            socket.send(JSON.stringify({
              type: 'system',
              content: `Welcome back, ${decoded.username}!`
            }));
            
            // Send online users immediately upon login
            broadcastOnlineUsers();
            
            // Send user's chats
            const userChats = Array.from(chatRooms.values())
              .filter(chat => chat.participants.includes(decoded.username))
              .map(chat => {
                // Format chats for client
                const otherParticipants = chat.participants.filter(p => p !== decoded.username);
                
                return {
                  _id: chat.id,
                  name: chat.name || (chat.type === 'direct' ? otherParticipants[0] : 'Group Chat'),
                  type: chat.type,
                  participants: chat.participants,
                  otherParticipants,
                  created: chat.created,
                  lastMessage: chat.messages.length > 0 ? chat.messages[chat.messages.length - 1] : null
                };
              });
            
            socket.send(JSON.stringify({
              type: 'chats',
              chats: userChats
            }));
          } catch (error) {
            console.error('Authentication error:', error.message);
            socket.send(JSON.stringify({
              type: 'error',
              message: 'Invalid or expired token'
            }));
          }
          break;
          
        // Add other message handlers below...
        // ... existing code ...
      }
    } catch (error) {
      console.error('Error processing message:', error);
      socket.send(JSON.stringify({
        type: 'error',
        message: 'Error processing message'
      }));
    }
  });
  
  // Handle disconnection
  socket.on('close', () => {
    const clientData = connections.get(socket);
    
    if (clientData && clientData.authenticated && clientData.username) {
      console.log(`User disconnected: ${clientData.username}`);
      
      // Remove from connections
      connections.delete(socket);
      
      // Broadcast updated online users
      setTimeout(() => {
        broadcastOnlineUsers();
      }, 1000);
    } else {
      connections.delete(socket);
    }
  });
  
  // Handle errors
  socket.on('error', (error) => {
    console.error('WebSocket error:', error);
    try {
      socket.terminate();
    } catch (e) {
      // Ignore errors when terminating an already closed connection
    }
    connections.delete(socket);
  });
});

// Graceful shutdown handling
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

function gracefulShutdown() {
  console.log('Shutting down server...');
  
  // Clear ping interval
  if (pingInterval) {
    clearInterval(pingInterval);
  }
  
  // Close all WebSocket connections
  connections.forEach((clientData, client) => {
    try {
      client.close(1000, 'Server shutting down');
    } catch (error) {
      console.error('Error closing connection during shutdown:', error);
    }
  });
  
  // Close HTTP server
  server.close(() => {
    console.log('Server shutdown complete');
    process.exit(0);
  });
  
  // Force exit after 5 seconds if graceful shutdown fails
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 5000);
}

// Update file upload endpoint
app.post('/api/upload', (req, res, next) => {
  // Ensure proper error handling for multer
  upload.single('file')(req, res, (err) => {
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({ 
        error: err.message || 'File upload failed',
        details: err
      });
    }
    next();
  });
}, async (req, res) => {
  try {
    console.log('File upload request received');
    
    if (!req.file) {
      console.error('No file received in request');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log('File upload successful:', {
      path: req.file.path,
      filename: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    // Check file size (10MB limit)
    if (req.file.size > 10 * 1024 * 1024) {
      console.error('File size too large:', req.file.size);
      return res.status(400).json({ error: 'File size must be less than 10MB' });
    }

    // Check file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      console.error('Invalid file type:', req.file.mimetype);
      return res.status(400).json({ error: 'Invalid file type. Only images, PDFs, and Word documents are allowed.' });
    }

    // Set proper content type
    res.setHeader('Content-Type', 'application/json');
    
    res.json({
      fileUrl: req.file.path,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      fileType: req.file.mimetype
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ 
      error: 'File upload failed',
      details: error.message 
    });
  }
}); 