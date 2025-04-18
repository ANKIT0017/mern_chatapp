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
  type: { type: String, required: true },
  content: { type: String, required: true },
  sender: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  readBy: [{ type: String }], // List of usernames who have read this message
  deletedFor: [{ type: String }] // List of usernames who have deleted this message
});

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);

// Enable CORS
app.use(cors());
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

          // Extract chat ID and message content
          const { chatId, content } = data;
          
          if (!chatId || !content) {
            console.error('Missing chatId or content:', data);
            ws.send(JSON.stringify({
              type: 'error',
              content: 'Missing chatId or message content'
            }));
            return;
          }
          
          try {
            // Check if user is part of this chat
            const chat = await Chat.findById(chatId);
            if (!chat) {
              console.error('Chat not found:', chatId);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'Chat not found'
              }));
              return;
            }
            
            if (!chat.participants.includes(user.username)) {
              console.error('User not in chat participants:', user.username, chat.participants);
              ws.send(JSON.stringify({
                type: 'error',
                content: 'You are not a participant in this chat'
              }));
              return;
            }
            
            // Create and save the message
            const messageData = {
              chatId,
              type: 'message',
              content,
              sender: user.username,
              timestamp: new Date(),
              readBy: [user.username]
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
                chatId: ensureStringId(chat._id),
                messageData: {
                  ...messageData,
                  _id: ensureStringId(newMessage._id),
                  chatId: ensureStringId(messageData.chatId),
                  timestamp: messageData.timestamp.toISOString()
                }
              };

              console.log('Broadcasting message to chat participants:', chat.participants);
              
              // Track which users have received the message
              const messageReceivedBy = new Set();
              
              // Broadcast to all participants of this chat who are online
              chat.participants.forEach(participant => {
                const participantSession = userSessions.get(participant);
                if (participantSession) {
                  // Find all WebSocket connections for this participant
                  clients.forEach((clientInfo, clientWs) => {
                    if (clientInfo.user && 
                        clientInfo.user.username === participant && 
                        clientWs.readyState === WebSocket.OPEN &&
                        !messageReceivedBy.has(participant)) {
                      
                      clientWs.send(JSON.stringify(broadcastMessage));
                      messageReceivedBy.add(participant);
                      
                      // If not the sender, also send a notification message
                      if (participant !== user.username) {
                        const notificationMessage = {
                          type: 'notification',
                          chatId: ensureStringId(chat._id),
                          sender: user.username,
                          content: content.substring(0, 50) + (content.length > 50 ? '...' : ''),
                          timestamp: new Date().toISOString()
                        };
                        clientWs.send(JSON.stringify(notificationMessage));
                      }
                    }
                  });
                }
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
              await Message.updateMany(
                { 
                  chatId,
                  readBy: { $ne: user.username }
                },
                { 
                  $addToSet: { readBy: user.username } 
                }
              );
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
              
              // Check if chat already exists
              const existingChat = await Chat.findOne({
                type: 'direct',
                participants: { $all: [user.username, otherUser], $size: 2 }
              });
              
              if (existingChat) {
                newChat = existingChat;
              } else {
                // Create new direct chat
                newChat = new Chat({
                  type: 'direct',
                  name: `${user.username}_${otherUser}`,
                  participants: [user.username, otherUser],
                  createdBy: user.username
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
                createdBy: user.username
              });
              
              await newChat.save();
              
              // Notify other participants about the new chat
              for (const participant of allParticipants) {
                if (participant !== user.username) {
                  const participantSession = userSessions.get(participant);
                  if (participantSession) {
                    clients.forEach((clientInfo, clientWs) => {
                      if (clientInfo.user.username === participant && clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'new_chat',
                          chat: {
                            ...newChat.toObject(),
                            lastMessage: null
                          }
                        }));
                      }
                    });
                  }
                }
              }
            }
            
            // Send the new chat to the creator
            ws.send(JSON.stringify({
              type: 'new_chat',
              chat: {
                ...newChat.toObject(),
                lastMessage: null
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