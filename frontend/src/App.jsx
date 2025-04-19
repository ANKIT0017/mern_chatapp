import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  ChakraProvider, 
  Box, 
  Container, 
  Input, 
  Button, 
  VStack, 
  Text, 
  Flex, 
  useToast,
  Badge,
  HStack,
  Avatar,
  AvatarGroup,
  IconButton,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Drawer,
  DrawerBody,
  DrawerHeader,
  DrawerOverlay,
  DrawerContent,
  DrawerCloseButton,
  useDisclosure,
  FormControl,
  FormLabel,
  Select,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Tooltip,
  Heading,
  MenuDivider,
  Textarea,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  Progress,
  Popover,
  PopoverTrigger,
  PopoverContent,
  PopoverBody,
  PopoverArrow,
  Link,
  Icon
} from '@chakra-ui/react';
import { keyframes } from '@emotion/react';
import { AddIcon, SettingsIcon, BellIcon, EditIcon, DeleteIcon, AttachmentIcon, CheckIcon } from '@chakra-ui/icons';
import AuthForm from './components/AuthForm';
import UserProfile from './components/UserProfile';
import { FaPaperPlane } from 'react-icons/fa';
import { FiPaperclip, FiEdit2, FiTrash2, FiCheck } from 'react-icons/fi';

// Optional: If you have a notification sound file in your public folder
// Uncomment this line to add notification sounds
// import notificationSound from './assets/notification.mp3';

const App = () => {
  // Move all state declarations to the top
  const [message, setMessage] = useState('');
  const [messageHistory, setMessageHistory] = useState({});
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [availableUsers, setAvailableUsers] = useState([]);
  const [chats, setChats] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [chatMessages, setChatMessages] = useState({});
  const [unreadCounts, setUnreadCounts] = useState({});
  const [notifications, setNotifications] = useState([]);
  const [viewMembersOpen, setViewMembersOpen] = useState(false);
  const [chatMembers, setChatMembers] = useState([]);
  const [editingMessage, setEditingMessage] = useState(null);
  const [editText, setEditText] = useState('');
  const [typingUsers, setTypingUsers] = useState({});
  const [uploadProgress, setUploadProgress] = useState(0);
  const [profileUser, setProfileUser] = useState(null); // Added for user profile viewing

  // Move all refs to the top
  const ws = useRef(null);
  const toast = useToast();
  const messagesEndRef = useRef(null);
  const logoutRef = useRef(null);
  const messageInputRef = useRef(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimeout = useRef(null);
  const connectionStartTime = useRef(null);
  const lastActivity = useRef(Date.now());
  const keepaliveInterval = useRef(null);
  const connectionTimeout = useRef(null);
  const connectWebSocketRef = useRef(null);
  const handleReconnectRef = useRef(null);
  const lastTokenRefresh = useRef(0);
  const isRefreshingToken = useRef(false);
  const successfulConnections = useRef(0);
  const lastSuccessfulConnection = useRef(0);
  const recentSystemMessages = useRef([]);
  const typingTimeoutRef = useRef(null);
  const fileInputRef = useRef(null);

  // Drawer state
  const { 
    isOpen: isNewChatOpen, 
    onOpen: onNewChatOpen, 
    onClose: onNewChatClose 
  } = useDisclosure();
  
  // Profile modal state
  const {
    isOpen: isProfileOpen,
    onOpen: onProfileOpen,
    onClose: onProfileClose
  } = useDisclosure();
  
  // Form states for creating chats
  const [selectedUser, setSelectedUser] = useState('');
  const [groupName, setGroupName] = useState('');
  const [selectedGroupMembers, setSelectedGroupMembers] = useState([]);

  // WebSocket connection management
  const [wsStatus, setWsStatus] = useState('disconnected');
  const MAX_RECONNECT_ATTEMPTS = 20; // Reduced max reconnect attempts to avoid excessive reconnection
  const RECONNECT_DELAY = 5000; // Initial delay of 5 seconds
  const MAX_SYSTEM_MESSAGES = 2;
  const PING_INTERVAL = 60000; // Increase to 60 seconds to reduce network traffic
  const CONNECTION_TIMEOUT = 20000; // Increase to 20 seconds for slower connections

  // Add rate limiting for token refresh
  const MIN_REFRESH_INTERVAL = 60000; // Increase to 60 seconds to reduce token refresh frequency

  // You can use this if you have a notification sound file
  // const [playNotificationSound] = useSound(notificationSound);

  // Add effect for message input focus
  useEffect(() => {
    if (activeChat && messageInputRef.current) {
      messageInputRef.current.focus();
    }
  }, [activeChat]);

  // Add effect for clearing message when changing chats
  useEffect(() => {
    setMessage('');
  }, [activeChat]);

  // Add effect to reset online users when user changes
  useEffect(() => {
    // If user is null (logged out), clear online users
    if (!user) {
      setOnlineUsers([]);
    }
  }, [user]);

  // Basic utility functions first
  const showNotification = useCallback((sender, message, chatId) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(`New message from ${sender}`, {
        body: message,
        icon: '/logo.png'
      });
    }
    
    toast({
      title: `New message from ${sender}`,
      description: message,
      status: 'info',
      duration: 5000,
      isClosable: true,
      position: 'top-right',
      onClick: () => {
        setActiveChat(chatId);
        if (document.hidden) {
          window.focus();
        }
      }
    });
    
    setNotifications(prev => [
      {
        id: Date.now(),
        sender,
        message,
        chatId,
        timestamp: new Date()
      },
      ...prev.slice(0, 9)
    ]);
  }, [toast]);

  // Message handling functions
  const handleChatMessage = useCallback((data) => {
    if (!data.chatId || !user) return;

    // Handle chat history messages
    if (data.type === 'chat_history') {
      if (data.chatId && data.messages && Array.isArray(data.messages)) {
        const validMessages = data.messages.filter(msg => msg.sender && typeof msg.sender === 'string');
        
        // Log file messages for debugging
        validMessages.forEach(msg => {
          if (msg.type === 'file') {
            console.log('Received file message:', {
              id: msg._id,
              content: msg.content,
              fileUrl: msg.fileUrl,
              fileName: msg.fileName,
              fileType: msg.fileType
            });
          }
        });
        
        setChatMessages(prev => ({
          ...prev,
          [data.chatId]: validMessages
        }));
        
        setTimeout(() => {
          messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      }
      return;
    }

    // If it's a file message, log it
    if (data.messageData && data.messageData.type === 'file') {
      console.log('Received new file message:', {
        id: data.messageData._id,
        content: data.messageData.content,
        fileUrl: data.messageData.fileUrl,
        fileName: data.messageData.fileName,
        fileType: data.messageData.fileType
      });
    }

    // Handle edited messages
    if (data.type === 'message_edited') {
      setChatMessages(prev => {
        const chatMessages = prev[data.chatId] || [];
        return {
          ...prev,
          [data.chatId]: chatMessages.map(msg => 
            msg._id === data.messageId 
              ? { 
                  ...msg, 
                  content: data.content,
                  isEdited: true,
                  editedAt: data.editedAt,
                  editHistory: data.editHistory
                }
              : msg
          )
        };
      });

      // Update chat list if it was the last message
      setChats(prevChats => {
        return prevChats.map(chat => {
          if (chat._id === data.chatId && chat.lastMessage?._id === data.messageId) {
            return {
              ...chat,
              lastMessage: {
                ...chat.lastMessage,
                content: data.content,
                isEdited: true,
                editedAt: data.editedAt
              }
            };
          }
          return chat;
        });
      });
    }
    
    // Handle deleted messages
    if (data.type === 'message_deleted') {
      console.log('Message deleted received in handleChatMessage:', data);
      
      setChatMessages(prev => {
        const chatMessages = prev[data.chatId] || [];
        return {
          ...prev,
          [data.chatId]: chatMessages.map(msg => 
            msg._id === data.messageId
              ? {
                  ...msg,
                  content: 'This message has been deleted',
                  type: 'deleted',
                  isDeleted: true,
                  deletedAt: data.deletedAt
                }
              : msg
          )
        };
      });

      // Update chat list if it was the last message
      setChats(prevChats => {
        return prevChats.map(chat => {
          if (chat._id === data.chatId && chat.lastMessage?._id === data.messageId) {
            return {
              ...chat,
              lastMessage: {
                ...chat.lastMessage,
                content: 'This message has been deleted',
                type: 'deleted',
                isDeleted: true,
                deletedAt: data.deletedAt
              }
            };
          }
          return chat;
        });
      });
      
      return; // Return after handling deletion
    }

    // Handle new messages
    if (data.type === 'chat_message') {
      if (data.messageData) {
        // Log message data for debugging
        console.log('Received message data:', data.messageData);
        
        // Add message to chat messages
        setChatMessages(prev => {
          const chatMessages = prev[data.chatId] || [];
          
          // Check for duplicate message
          const isDuplicate = chatMessages.some(msg => msg._id === data.messageData._id);
          if (isDuplicate) {
            return prev;
          }
          
          return {
            ...prev,
            [data.chatId]: [...chatMessages, data.messageData]
          };
        });
        
        // Update chat list
        setChats(prevChats => {
          const updatedChats = prevChats.map(chat => {
            if (chat._id === data.chatId) {
              return {
                ...chat,
                lastMessage: data.messageData,
                lastActivity: new Date().toISOString()
              };
            }
            return chat;
          });
          return updatedChats;
        });
        
        // Handle notifications for messages not from the current user
        if (data.messageData.sender !== user.username) {
          // Show notification if not in the active chat
          if (data.chatId !== activeChat || document.hidden) {
            showNotification(
              data.messageData.sender, 
              data.messageData.type === 'file' 
                ? `[File] ${data.messageData.content}`
                : data.messageData.content,
              data.chatId
            );
            
            // Increment unread count if it's not the active chat
            if (data.chatId !== activeChat) {
              setUnreadCounts(prev => ({
                ...prev,
                [data.chatId]: (prev[data.chatId] || 0) + 1
              }));
            }
          }
        }
        
        // Scroll to bottom after message is added
        setTimeout(() => {
          messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      }
    }
  }, [activeChat, user, showNotification]);

  // Update handleSystemMessage to ignore join/leave messages
  const handleSystemMessage = useCallback((data) => {
    if (!data.content) return;
    
    // Skip join/leave notifications
    if (data.content.includes('has joined') || data.content.includes('has left')) {
      return;
    }
    
    const now = Date.now();
    recentSystemMessages.current = [
      ...recentSystemMessages.current.filter(msg => now - msg.time < 30000),
      { content: data.content, time: now }
    ];
    
    if (recentSystemMessages.current.length <= MAX_SYSTEM_MESSAGES) {
      toast({
        description: data.content,
        status: 'info',
        duration: 3000,
        isClosable: true,
        position: 'bottom',
      });
    }
  }, [toast]);

  // Move refreshAccessToken definition before any useEffects that use it
  const refreshAccessToken = useCallback(async () => {
    try {
      if (isRefreshingToken.current) {
        console.log('Token refresh already in progress, skipping');
        return false;
      }

      const now = Date.now();
      if (now - lastTokenRefresh.current < MIN_REFRESH_INTERVAL) {
        console.log('Token refresh too frequent, skipping');
        return false;
      }

      const storedRefreshToken = refreshToken || localStorage.getItem('refreshToken');
      
      if (!storedRefreshToken) {
        console.error('No refresh token available');
        return false;
      }
      
      isRefreshingToken.current = true;

      const response = await fetch('http://localhost:5000/api/refresh-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken: storedRefreshToken }),
      });
      
      if (!response.ok) {
        if (response.status === 429) {
          console.log('Rate limited, waiting before retry');
          return false;
        }
        throw new Error(`Failed to refresh token: ${response.status}`);
      }
      
      const data = await response.json();
      
      setAccessToken(data.accessToken);
      setRefreshToken(data.refreshToken);
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      
      lastTokenRefresh.current = now;
      
      // Reconnect WebSocket with new token
      if (ws.current) {
        ws.current.close(1000, "Token refreshed");
      }
      
      setTimeout(() => {
        if (connectWebSocketRef.current) {
          connectWebSocketRef.current();
        }
      }, 1000);
      
      return true;
    } catch (error) {
      console.error('Error refreshing token:', error);
      // Only logout if refresh token is invalid or expired
      if (error.message.includes('401') || error.message.includes('403')) {
        if (logoutRef.current) {
          logoutRef.current();
        }
      }
      return false;
    } finally {
      isRefreshingToken.current = false;
    }
  }, [refreshToken]);

  // Session restoration effect
  useEffect(() => {
    const restoreSession = async () => {
      const savedAccessToken = localStorage.getItem('accessToken');
      const savedRefreshToken = localStorage.getItem('refreshToken');
      const savedUser = localStorage.getItem('user');

      if (savedAccessToken && savedRefreshToken && savedUser) {
        try {
          // First try to use the existing access token
          const response = await fetch('http://localhost:5000/api/users', {
            headers: {
              'Authorization': `Bearer ${savedAccessToken}`
            }
          });

          if (response.ok) {
            // Access token is still valid
            setAccessToken(savedAccessToken);
            setRefreshToken(savedRefreshToken);
            setUser(JSON.parse(savedUser));
          } else {
            // Access token expired, try to refresh
            const success = await refreshAccessToken();
            if (!success) {
              // If refresh fails, clear storage
              localStorage.removeItem('accessToken');
              localStorage.removeItem('refreshToken');
              localStorage.removeItem('user');
            }
          }
        } catch (error) {
          console.error('Error restoring session:', error);
        }
      }
    };

    restoreSession();
  }, [refreshAccessToken]); // Add refreshAccessToken as dependency

  // Auto refresh effect
  useEffect(() => {
    if (user && accessToken) {
      // Set up automatic token refresh
      const refreshInterval = setInterval(async () => {
        // Refresh token 5 minutes before it expires (assuming 15 min expiry)
        const success = await refreshAccessToken();
        if (!success) {
          console.error('Failed to refresh token');
        }
      }, 10 * 60 * 1000); // 10 minutes (reduced frequency)

      return () => clearInterval(refreshInterval);
    }
  }, [user, accessToken, refreshAccessToken]);

  // Update handleLogout to ensure proper cleanup
  const handleLogout = useCallback(async () => {
    console.log('Handling logout for user:', user?.username);
    
    // First, stop all reconnection attempts and intervals
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }
    
    if (keepaliveInterval.current) {
      clearInterval(keepaliveInterval.current);
      keepaliveInterval.current = null;
    }
    
    if (connectionTimeout.current) {
      clearTimeout(connectionTimeout.current);
      connectionTimeout.current = null;
    }
    
    // Reset reconnection attempts
    reconnectAttempts.current = 0;
    
    try {
      // Send logout message through WebSocket first if connected
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        try {
          // Send the logout message and wait a moment to ensure it's processed
          ws.current.send(JSON.stringify({
            type: 'logout',
            token: accessToken
          }));
          
          // Give server a moment to process the logout message
          await new Promise(resolve => setTimeout(resolve, 500));
        } catch (e) {
          console.error('Error sending WebSocket logout:', e);
        }
      }

      // Close WebSocket connection properly
      if (ws.current) {
        try {
          ws.current.onclose = null; // Remove close handler to prevent reconnection attempts
          ws.current.close(1000, "User logout");
        } catch (e) {
          console.error('Error closing WebSocket during logout:', e);
        }
        ws.current = null;
      }

      // Only call logout endpoint if we have tokens (avoid unnecessary requests)
      if (accessToken && refreshToken) {
        try {
          const response = await fetch('http://localhost:5000/api/logout', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({ refreshToken })
          });
          
          if (!response.ok && response.status !== 429) {
            console.warn(`Logout API response: ${response.status}`);
          }
        } catch (error) {
          console.error('Logout API error:', error);
        }
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear all stored tokens and user data
      localStorage.clear(); // Clear all stored data
      
      // Reset all state
      setAccessToken(null);
      setRefreshToken(null);
      setUser(null);
      setChats([]);
      setChatMessages({});
      setActiveChat(null);
      setOnlineUsers([]); // Clear online users immediately on the client side
      setNotifications([]);
      
      setWsStatus('disconnected');
    }
  }, [accessToken, refreshToken, user]);

  // Update the ref when handleLogout changes
  useEffect(() => {
    logoutRef.current = handleLogout;
  }, [handleLogout]);

  // Token and authentication functions
  const handleLogin = useCallback((newAccessToken, newRefreshToken, userData) => {
    console.log('Handling login for user:', userData.username);
    setAccessToken(newAccessToken);
    setRefreshToken(newRefreshToken);
    setUser(userData);
    localStorage.setItem('accessToken', newAccessToken);
    localStorage.setItem('refreshToken', newRefreshToken);
    localStorage.setItem('user', JSON.stringify(userData));
    
    // Clear previous data on new login
    setChats([]);
    setChatMessages({});
    setActiveChat(null);
    setOnlineUsers([]);
    setNotifications([]);
    reconnectAttempts.current = 0; // Reset reconnect attempts

    // Ensure existing connection is closed before creating a new one
    if (ws.current) {
      console.log('Closing existing WebSocket connection before new login.');
      ws.current.close(1000, "New login");
    }
    
    // Short delay before establishing new connection
    setTimeout(() => {
      if (connectWebSocketRef.current) {
        connectWebSocketRef.current();
      }
    }, 500);
  }, []);

  // Connection management functions
  const handleReconnect = useCallback((forceBackoff = false) => {
    // Don't attempt to reconnect if we're already in the process of reconnecting
    if (reconnectTimeout.current) {
      console.log("Reconnection already in progress, not scheduling another");
      return;
    }
    
    // Don't attempt reconnection if we're refreshing a token
    if (isRefreshingToken.current) {
      console.log("Token refresh in progress, delaying reconnection");
      reconnectTimeout.current = setTimeout(() => {
        reconnectTimeout.current = null;
        if (handleReconnectRef.current) {
          handleReconnectRef.current(forceBackoff);
        }
      }, 5000); // Wait 5 seconds and try again
      return;
    }
    
    reconnectAttempts.current += 1;
    
    // Calculate delay with exponential backoff but with a more gradual increase
    // and a higher maximum delay for stability
    let delay = RECONNECT_DELAY;
    if (forceBackoff || reconnectAttempts.current > 2) {
      // More gradual exponential backoff with longer waits between attempts
      // 5s, 15s, 30s, 60s, 120s, 300s (5 min max)
      delay = Math.min(300000, Math.pow(2, Math.min(reconnectAttempts.current, 6)) * RECONNECT_DELAY);
    }
    
    console.log(`Scheduling reconnection attempt ${reconnectAttempts.current} in ${delay}ms`);
    setWsStatus('reconnecting');
    
    // Check if we need to refresh the token before reconnection
    const tokenRefreshNeeded = accessToken && !isRefreshingToken.current && 
      (Date.now() - lastTokenRefresh.current > 5 * 60 * 1000); // If token is older than 5 minutes
    
    // Only attempt to reconnect if we haven't exceeded the maximum attempts
    // or if we're within a reasonable time window of the last successful connection
    const shouldAttemptReconnect = 
      reconnectAttempts.current <= MAX_RECONNECT_ATTEMPTS ||
      (lastSuccessfulConnection.current && (Date.now() - lastSuccessfulConnection.current < 3600000)); // 1 hour
    
    if (shouldAttemptReconnect) {
      reconnectTimeout.current = setTimeout(async () => {
        if (user && accessToken) {
          console.log(`Attempting reconnection ${reconnectAttempts.current}`);
          
          // Try to refresh token if needed but not too frequently
          if (tokenRefreshNeeded) {
            try {
              console.log('Refreshing token before reconnection attempt');
              const success = await refreshAccessToken();
              if (!success) {
                console.log('Token refresh failed, continuing with reconnection anyway');
              }
            } catch (e) {
              console.error('Error refreshing token before reconnection:', e);
            }
          }
          
          if (connectWebSocketRef.current) {
            reconnectTimeout.current = null; // Clear reference before attempting new connection
            connectWebSocketRef.current();
          }
        } else {
          reconnectTimeout.current = null;
          setWsStatus('disconnected');
        }
      }, delay);
    } else {
      console.log('Exceeded maximum reconnection attempts or reconnection window');
      setWsStatus('disconnected');
      // Reset attempt count after a long delay to allow future reconnection attempts
      setTimeout(() => {
        reconnectAttempts.current = 0;
      }, 600000); // Reset after 10 minutes
    }
  }, [user, accessToken, MAX_RECONNECT_ATTEMPTS, RECONNECT_DELAY, refreshAccessToken]);

  // WebSocket connection function
  const connectWebSocket = useCallback(() => {
    if (!accessToken) {
      console.log('No access token available, skipping WebSocket connection');
      return;
    }

    // Don't try to connect if we're refreshing the token
    if (isRefreshingToken.current) {
      console.log('Token refresh in progress, delaying connection');
      return;
    }

    // Prevent duplicate connection attempts
    if (ws.current && (ws.current.readyState === WebSocket.CONNECTING || ws.current.readyState === WebSocket.OPEN)) {
      console.log('WebSocket already connected or connecting, skipping connection attempt');
      return;
    }

    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }
    
    if (connectionTimeout.current) {
      clearTimeout(connectionTimeout.current);
      connectionTimeout.current = null;
    }
    
    // Set a connection timeout
    connectionTimeout.current = setTimeout(() => {
      if (ws.current && ws.current.readyState !== WebSocket.OPEN) {
        console.log('Connection attempt timed out');
        setWsStatus('error');
        
        // Force close the socket
        try {
          ws.current.close(1006, "Connection timeout");
        } catch (e) {
          console.error('Error closing timed out WebSocket:', e);
        }
        
        // Attempt to reconnect
        if (handleReconnectRef.current) {
          handleReconnectRef.current(true);
        }
      }
    }, CONNECTION_TIMEOUT);
    
    // Add connection parameters to prevent caching and track sessions
    const uniqueId = Date.now() + Math.random().toString(36).substr(2, 9);
    const reconnectCount = reconnectAttempts.current;
    const timestamp = Date.now();
    
    // Get the current host for WebSocket connections
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = process.env.REACT_APP_API_HOST || window.location.hostname;
    const port = process.env.REACT_APP_API_PORT || '5000';
    const socketUrl = `${protocol}//${host}:${port}?id=${uniqueId}&reconnect=${reconnectCount}&t=${timestamp}`;
    
    console.log(`Connecting to WebSocket at ${socketUrl}`);
    
    try {
      // Only close existing connection if actually open
      if (ws.current) {
        if (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING) {
          console.log('Closing existing WebSocket connection before creating a new one.');
          try {
            ws.current.close(1000, "Replaced by new connection");
          } catch (e) {
            console.error('Error closing previous connection:', e);
          }
        }
        // Wait a moment before creating a new connection
        setTimeout(() => createNewConnection(), 500);
      } else {
        createNewConnection();
      }
    } catch (error) {
      console.error('Error establishing WebSocket connection:', error);
      setWsStatus('error');
      if (handleReconnectRef.current) {
        handleReconnectRef.current(true);
      }
    }
    
    function createNewConnection() {
      try {
        // Create new WebSocket connection
        ws.current = new WebSocket(socketUrl);
        ws.current.binaryType = 'arraybuffer';
        setWsStatus('connecting');
        connectionStartTime.current = Date.now();
        lastActivity.current = Date.now();
        
        // Handle connection opening
        ws.current.onopen = () => {
          const connectTime = Date.now() - connectionStartTime.current;
          console.log(`WebSocket connected in ${connectTime}ms`);
          setWsStatus('connected');
          reconnectAttempts.current = 0;
          successfulConnections.current++;
          lastSuccessfulConnection.current = Date.now();
          
          if (connectionTimeout.current) {
            clearTimeout(connectionTimeout.current);
            connectionTimeout.current = null;
          }
          
          // Send login message immediately after connection
          if (accessToken) {
            console.log('WebSocket connected, sending login message');
            try {
              ws.current.send(JSON.stringify({
                type: 'login',
                token: accessToken,
                clientInfo: {
                  userAgent: navigator.userAgent,
                  timestamp: Date.now(),
                  connectionId: uniqueId,
                  reconnectCount: reconnectCount,
                  connectionTime: connectTime
                }
              }));
            } catch (e) {
              console.error('Error sending login message:', e);
              if (handleReconnectRef.current) {
                handleReconnectRef.current();
              }
              return;
            }
          }
          
          // Setup keepalive interval
          if (keepaliveInterval.current) {
            clearInterval(keepaliveInterval.current);
          }
          
          keepaliveInterval.current = setInterval(() => {
            if (ws.current && ws.current.readyState === WebSocket.OPEN) {
              const now = Date.now();
              try {
                ws.current.send(JSON.stringify({ 
                  type: 'ping', 
                  timestamp: now,
                  connectionId: uniqueId
                }));
                lastActivity.current = now;
              } catch (e) {
                console.error('Error sending ping:', e);
                if (handleReconnectRef.current) {
                  handleReconnectRef.current();
                }
              }
            }
          }, PING_INTERVAL);
        };
  
        // Other handlers remain the same...
        // (update: ws.current.onmessage, ws.current.onclose, ws.current.onerror)
        
        // WebSocket message handler
        ws.current.onmessage = async (event) => {
          try {
            const data = JSON.parse(event.data);
            lastActivity.current = Date.now();
    
            if (data.type === 'error' && (data.message === 'Invalid or expired token' || data.content === 'Invalid or expired token')) {
              // Only attempt refresh if we haven't tried too recently
              if (Date.now() - lastTokenRefresh.current >= MIN_REFRESH_INTERVAL) {
                console.log('Token expired, attempting to refresh...');
                const success = await refreshAccessToken();
                if (!success) {
                  console.log('Token refresh failed, logging out...');
                  if (logoutRef.current) {
                    logoutRef.current();
                  }
                }
              } else {
                console.log('Token refresh attempted too recently, waiting...');
              }
              return;
            }
    
            switch (data.type) {
              case 'users':
                setAvailableUsers(data.users);
                break;
              case 'chat_members':
                setChatMembers(data.members);
                break;
              case 'chat_cleared':
                setChatMessages(prev => ({
                  ...prev,
                  [data.chatId]: []
                }));
                break;
              case 'chat_deleted':
                setChats(prev => prev.filter(chat => chat._id !== data.chatId));
                if (activeChat === data.chatId) {
                  setActiveChat(null);
                }
                break;
              case 'onlineUsers':
                // Filter out any duplicate users and the current user
                const uniqueUsers = Array.from(new Set(data.users || []));
                // If we're logged out, don't show any online users
                // Otherwise remove the current user from the list
                const otherOnlineUsers = user 
                  ? uniqueUsers.filter(u => u !== user.username)
                  : []; // If logged out, don't show anyone as online
                
                console.log('Received online users:', uniqueUsers, 'filtered to:', otherOnlineUsers);
                setOnlineUsers(otherOnlineUsers);
                break;
              case 'ping':
                if (ws.current && ws.current.readyState === WebSocket.OPEN) {
                  ws.current.send(JSON.stringify({ 
                    type: 'pong', 
                    timestamp: Date.now(),
                    received: data.timestamp,
                    latency: data.timestamp ? Date.now() - data.timestamp : null,
                    connectionId: uniqueId
                  }));
                }
                break;
              case 'pong':
                if (data.received) {
                  const latency = Date.now() - data.received;
                  if (latency > 1000) {
                    console.warn(`High WebSocket latency: ${latency}ms`);
                  }
                }
                break;
              case 'hello':
                console.log('Connected to server');
                break;
              case 'chats':
                if (data.chats && Array.isArray(data.chats)) {
                  setChats(data.chats);
                }
                break;
              case 'chat_history':
                handleChatMessage({
                  type: 'chat_history',
                  chatId: data.chatId,
                  messages: data.messages
                });
                break;
              case 'chat_message':
                handleChatMessage(data);
                break;
              case 'message':
                handleChatMessage({
                  type: 'chat_message',
                  chatId: data.chatId,
                  messageData: data
                });
                break;
              case 'new_chat':
                console.log('New chat received:', data.chat);
                // Add the new chat to the chat list while handling duplicates
                setChats(prevChats => {
                  // Check if this exact chat already exists
                  const chatExists = prevChats.some(chat => chat._id === data.chat._id);
                  if (chatExists) {
                    return prevChats;
                  }
                  
                  // Identify any temporary chat that might be for the same conversation
                  // For direct chats, check if both have the same participants
                  const hasSameParticipants = (chat1, chat2) => {
                    if (chat1.type !== chat2.type) return false;
                    if (chat1.type === 'direct' && chat2.type === 'direct') {
                      const chat1Participants = new Set(chat1.participants);
                      const chat2Participants = new Set(chat2.participants);
                      
                      // Check if both sets have the same participants
                      return chat1Participants.size === chat2Participants.size && 
                             [...chat1Participants].every(p => chat2Participants.has(p));
                    }
                    
                    // For group chats, check if they have the same name
                    if (chat1.type === 'group' && chat2.type === 'group') {
                      return chat1.name === chat2.name;
                    }
                    
                    return false;
                  };
                  
                  // First remove any temporary chat with same participants
                  const isTemp = id => typeof id === 'string' && id.startsWith('temp-');
                  const duplicateIndex = prevChats.findIndex(chat => 
                    isTemp(chat._id) && hasSameParticipants(chat, data.chat)
                  );
                  
                  // If a duplicate temporary chat is found, replace it with the real one
                  if (duplicateIndex >= 0) {
                    const tempChatId = prevChats[duplicateIndex]._id;
                    console.log(`Replacing temporary chat ${tempChatId} with real chat ${data.chat._id}`);
                    
                    // Update active chat if it was the temporary one
                    if (activeChat === tempChatId) {
                      // We'll need to update activeChat outside this function
                      setTimeout(() => setActiveChat(data.chat._id), 0);
                    }
                    
                    // Replace the temporary chat with the real one
                    const updatedChats = [...prevChats];
                    updatedChats[duplicateIndex] = data.chat;
                    return updatedChats;
                  }
                  
                  // Otherwise add as new chat at the beginning
                  return [data.chat, ...prevChats];
                });
                break;
              case 'chat_updated':
                console.log('Chat updated received:', data.chat);
                // Update the chat in the chat list
                setChats(prevChats => {
                  // Check if chat exists in the list
                  const chatIndex = prevChats.findIndex(chat => chat._id === data.chat._id);
                  
                  // If chat exists, update it; otherwise, add it to the list
                  if (chatIndex >= 0) {
                    const updatedChats = [...prevChats];
                    updatedChats[chatIndex] = data.chat;
                    return updatedChats;
                  } else {
                    // Add new chat to the beginning of the list
                    return [data.chat, ...prevChats];
                  }
                });
                break;
              case 'system':
                handleSystemMessage(data);
                break;
              case 'typing_status':
                setTypingUsers(prev => {
                  const newTypingUsers = { ...prev };
                  if (data.chatId && data.username && data.username !== user?.username) {
                    if (!newTypingUsers[data.chatId]) {
                      newTypingUsers[data.chatId] = new Set();
                    }
                    
                    if (data.isTyping) {
                      newTypingUsers[data.chatId].add(data.username);
                    } else {
                      newTypingUsers[data.chatId].delete(data.username);
                      if (newTypingUsers[data.chatId].size === 0) {
                        delete newTypingUsers[data.chatId];
                      }
                    }
                  }
                  return newTypingUsers;
                });
                break;
              case 'message_edited':
                handleChatMessage(data);
                break;
              case 'message_deleted':
                // Don't call handleChatMessage, our direct event handler will handle it
                console.log('message_deleted event received in switch, dispatching direct event');
                break;
              case 'message_read':
                setChatMessages(prev => {
                  const chatMessages = prev[data.chatId] || [];
                  return {
                    ...prev,
                    [data.chatId]: chatMessages.map(msg => 
                      msg._id === data.messageId 
                        ? { 
                            ...msg, 
                            readBy: [...new Set([...msg.readBy, data.username])]
                          }
                        : msg
                    )
                  };
                });
                break;
              case 'temp_chat_replaced':
                // Handle replacement of temporary chat IDs with real server IDs
                console.log(`Replacing temporary chat ID ${data.tempId} with real ID ${data.realChatId}`);
                
                // Update active chat if it's the one being replaced
                if (activeChat === data.tempId) {
                  setActiveChat(data.realChatId);
                }
                
                // Update the chats list
                setChats(prevChats => {
                  return prevChats.map(chat => 
                    chat._id === data.tempId 
                      ? { ...chat, _id: data.realChatId }
                      : chat
                  );
                });
                
                // Move any messages from the temporary chat ID to the real one
                setChatMessages(prev => {
                  const tempMessages = prev[data.tempId] || [];
                  if (tempMessages.length === 0) return prev;
                  
                  // Create new object without the temp chat entry but with messages moved to real ID
                  const newMessages = { ...prev };
                  delete newMessages[data.tempId];
                  
                  // Update the chat ID in each message
                  newMessages[data.realChatId] = tempMessages.map(msg => ({
                    ...msg,
                    chatId: data.realChatId
                  }));
                  
                  return newMessages;
                });
                break;
              default:
                console.log('Unknown message type:', data.type);
            }
          } catch (error) {
            console.error('Error processing WebSocket message:', error);
          }
        };
        
        // Handle connection closing
        ws.current.onclose = (event) => {
          console.log(`WebSocket connection closed. Code: ${event.code} Reason: ${event.reason || 'No reason provided'}`);
          setWsStatus('disconnected');
          
          if (keepaliveInterval.current) {
            clearInterval(keepaliveInterval.current);
            keepaliveInterval.current = null;
          }
          
          // Check if this was a normal closure or if we need to reconnect
          const isNormalClosure = event.code === 1000 || event.code === 1001;
          const isUserLoggedIn = !!user;
          const isPageVisible = document.visibilityState === 'visible';
          
          // Only attempt to reconnect under specific conditions
          if (!isNormalClosure && isUserLoggedIn && isPageVisible && event.reason !== "Replaced by new connection") {
            console.log('Abnormal closure, attempting to reconnect...');
            // Use a slightly longer delay for onclose reconnection
            setTimeout(() => {
              if (handleReconnectRef.current) {
                handleReconnectRef.current(false);
              }
            }, 2000); // 2-second delay before reconnection
          } else {
            console.log(`Not reconnecting: normal=${isNormalClosure}, loggedIn=${isUserLoggedIn}, visible=${isPageVisible}, reason=${event.reason}`);
          }
        };
        
        // Handle connection errors
        ws.current.onerror = (error) => {
          console.error('WebSocket error occurred:', error);
          setWsStatus('error');
          
          // The onclose handler will be called after this and handle reconnection
        };
      } catch (error) {
        console.error('Error creating new WebSocket:', error);
        setWsStatus('error');
        if (handleReconnectRef.current) {
          handleReconnectRef.current(true);
        }
      }
    }
  }, [accessToken, user, refreshAccessToken, CONNECTION_TIMEOUT, PING_INTERVAL, MIN_REFRESH_INTERVAL, activeChat, handleSystemMessage, handleChatMessage]);

  // Update refs
  useEffect(() => {
    handleReconnectRef.current = handleReconnect;
  }, [handleReconnect]);

  useEffect(() => {
    connectWebSocketRef.current = connectWebSocket;
  }, [connectWebSocket]);

  // Request notification permissions
  useEffect(() => {
    if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
      Notification.requestPermission();
    }
  }, []);

  // Monitor document visibility changes
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        console.log('Page became visible, checking connection status');
        if (user && (!ws.current || ws.current.readyState !== WebSocket.OPEN)) {
          console.log('Connection lost while page was hidden, reconnecting...');
          reconnectAttempts.current = 0; // Reset attempts when user returns
          if (connectWebSocketRef.current) {
            connectWebSocketRef.current();
          }
        }
      }
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [user]);

  // Add connection status monitoring
  useEffect(() => {
    if (!user) return;

    const checkConnection = () => {
      if (ws.current) {
        const now = Date.now();
        const inactivityTime = now - lastActivity.current;
        
        // Only attempt to reconnect if there's been no activity for twice the ping interval
        // and the connection is not already in the process of connecting
        if (ws.current.readyState === WebSocket.OPEN && inactivityTime > PING_INTERVAL * 2) {
          console.log(`No activity for ${inactivityTime}ms, checking connection...`);
          try {
            // Send a ping to check if connection is still alive
            ws.current.send(JSON.stringify({ type: 'ping', timestamp: now }));
            // Update last activity time to prevent multiple pings
            lastActivity.current = now;
          } catch (error) {
            console.error('Error sending ping, connection may be dead:', error);
            if (handleReconnectRef.current) {
              handleReconnectRef.current(true);
            }
          }
        } else if (ws.current.readyState === WebSocket.CLOSED && wsStatus !== 'reconnecting') {
          // Only reconnect if we're not already in the process of reconnecting
          console.log('Connection is closed, attempting to reconnect...');
          if (handleReconnectRef.current) {
            handleReconnectRef.current(false);
          }
        }
        // Don't attempt to reconnect if already connecting
      } else if (user && wsStatus !== 'connecting' && wsStatus !== 'reconnecting') {
        console.log('No WebSocket instance found, creating new connection...');
        if (connectWebSocketRef.current) {
          connectWebSocketRef.current();
        }
      }
    };

    const intervalId = setInterval(checkConnection, PING_INTERVAL);
    
    return () => clearInterval(intervalId);
  }, [user, wsStatus, PING_INTERVAL, handleReconnectRef, connectWebSocketRef]);

  // Update the cleanup effect
  useEffect(() => {
    const savedAccessToken = localStorage.getItem('accessToken');
    if (user && savedAccessToken) {
      console.log('User logged in, connecting WebSocket.');
      if (connectWebSocketRef.current) {
        connectWebSocketRef.current();
      }
    }

    // Cleanup function
    return () => {
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
        reconnectTimeout.current = null;
      }
      
      if (keepaliveInterval.current) {
        clearInterval(keepaliveInterval.current);
        keepaliveInterval.current = null;
      }
      
      if (ws.current) {
        const socket = ws.current;
        // Only log and close if the socket is still connecting or open
        if (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN) {
          console.log('Cleaning up WebSocket connection...');
          socket.onclose = null; // Remove close handler to prevent reconnection attempts
          socket.close(1000, "Component unmounting");
        }
        ws.current = null;
      }
    };
  }, [user, connectWebSocketRef]);

  const selectChat = useCallback((chatId) => {
    console.log('Selecting chat:', chatId);
    setActiveChat(chatId);
    
    // Reset unread count when selecting a chat
    setUnreadCounts(prev => ({
      ...prev,
      [chatId]: 0
    }));
    
    // Always request chat history when selecting a chat
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      console.log('Requesting chat history for:', chatId);
      ws.current.send(JSON.stringify({
        type: 'join_chat',
        chatId
      }));
    }
  }, []);

  // Add a helper for sending messages
  const sendMessage = useCallback((content, chatId) => {
    if (!content.trim() || !chatId || !ws.current || ws.current.readyState !== WebSocket.OPEN) {
      return;
    }

    // Include originalChatId if it's a temporary ID to help server associate with real chat
    const isTemporaryChat = chatId.startsWith('temp-');
    
    ws.current.send(JSON.stringify({
      type: 'chat_message',
      chatId: chatId,
      content: content,
      ...(isTemporaryChat && { originalChatId: chatId })
    }));

    setMessage('');
    
    // Stop typing indicator
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
    
    ws.current.send(JSON.stringify({
      type: 'typing_stop',
      chatId: chatId
    }));
  }, []);

  const handleCreateGroupChat = useCallback(() => {
    if (!groupName || selectedGroupMembers.length === 0) {
      toast({
        title: "Error",
        description: "Please enter a group name and select at least one member",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
      return;
    }
    
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'create_chat',
        chatType: 'group',
        name: groupName,
        participants: selectedGroupMembers
      }));
      
      // Add optimistic update with structure matching server response
      const tempId = `temp-${Date.now()}`;
      const allParticipants = [...selectedGroupMembers, user.username];
      const newGroupChat = {
        _id: tempId,
        type: 'group',
        name: groupName,
        participants: allParticipants,
        otherParticipants: selectedGroupMembers, // Add otherParticipants array
        createdBy: user.username,
        lastMessage: null,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        unreadCount: 0 // Add unreadCount property
      };
      
      setChats(prevChats => [newGroupChat, ...prevChats]);
      setActiveChat(tempId);
      
      onNewChatClose();
      setGroupName('');
      setSelectedGroupMembers([]);
    }
  }, [groupName, selectedGroupMembers, user, ws, toast, onNewChatClose]);

  const handleCreateDirectChat = useCallback(() => {
    if (!selectedUser) {
      toast({
        title: "Error",
        description: "Please select a user",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
      return;
    }
    
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'create_chat',
        chatType: 'direct',
        participants: [selectedUser]
      }));
      
      // Add optimistic update with structure matching server response
      const tempId = `temp-${Date.now()}`;
      const newDirectChat = {
        _id: tempId,
        type: 'direct',
        name: `${user.username}_${selectedUser}`,
        participants: [user.username, selectedUser],
        otherParticipants: [selectedUser],
        createdBy: user.username,
        lastMessage: null,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        unreadCount: 0
      };
      
      setChats(prevChats => [newDirectChat, ...prevChats]);
      setActiveChat(tempId);
      
      onNewChatClose();
      setSelectedUser('');
    }
  }, [selectedUser, user, ws, toast, onNewChatClose]);

  const toggleGroupMember = (username) => {
    setSelectedGroupMembers(prev => 
      prev.includes(username)
        ? prev.filter(u => u !== username)
        : [...prev, username]
    );
  };

  useEffect(() => {
    const savedAccessToken = localStorage.getItem('accessToken');
    const savedRefreshToken = localStorage.getItem('refreshToken');
    const savedUser = localStorage.getItem('user');
    if (savedAccessToken && savedRefreshToken && savedUser) {
      setAccessToken(savedAccessToken);
      setRefreshToken(savedRefreshToken);
      try {
        setUser(JSON.parse(savedUser));
      } catch (error) {
        console.error('Error parsing user data:', error);
        // Clear invalid data from localStorage
        localStorage.removeItem('user');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
      }
    }
  }, []);

  // Chat list component
  const ChatsList = () => (
    <VStack spacing={3} align="stretch" overflowY="auto" h="calc(100vh - 200px)" px={2}>
      {chats.map((chat) => {
        const chatName = chat.type === 'direct' 
          ? chat.otherParticipants?.[0] || chat.name
          : chat.name;
          
        const unreadCount = unreadCounts[chat._id] || 0;
        const isOnline = chat.type === 'direct' && onlineUsers.includes(chatName);
        
        return (
          <Box 
            key={chat._id}
            p={4}
            bg={activeChat === chat._id ? "blue.50" : "white"}
            borderRadius="lg"
            cursor="pointer"
            _hover={{ 
              bg: activeChat === chat._id ? "blue.100" : "gray.50",
              transform: "translateY(-1px)",
              shadow: "sm"
            }}
            onClick={() => selectChat(chat._id)}
            position="relative"
            transition="all 0.2s"
            borderWidth="1px"
            borderColor={activeChat === chat._id ? "blue.200" : "gray.200"}
          >
            <HStack spacing={3} align="start">
              <Box position="relative">
                <Avatar 
                  name={chatName} 
                  bg={chat.type === 'group' ? "purple.500" : "blue.500"}
                  size="md"
                  src={chat.type === 'direct' 
                    ? availableUsers.find(u => u.username === chatName)?.avatar 
                    : chat.avatar} 
                />
                {isOnline && (
                  <Box
                    position="absolute"
                    bottom={0}
                    right={0}
                    w="3.5"
                    h="3.5"
                    bg="green.400"
                    borderRadius="full"
                    borderWidth="2px"
                    borderColor="white"
                  />
                )}
              </Box>
              <VStack spacing={0} align="start" flex={1}>
                <HStack spacing={2} width="100%" justify="space-between">
                  <Text fontWeight="semibold" fontSize="md">{chatName}</Text>
                  {chat.lastMessage && (
                    <Text fontSize="xs" color="gray.500">
                      {new Date(chat.lastMessage.timestamp).toLocaleTimeString([], { 
                        hour: '2-digit', 
                        minute: '2-digit' 
                      })}
                    </Text>
                  )}
                </HStack>
                {chat.lastMessage && (
                  <Text 
                    fontSize="sm" 
                    color={unreadCount > 0 ? "gray.900" : "gray.500"} 
                    noOfLines={1}
                    fontWeight={unreadCount > 0 ? "medium" : "normal"}
                    mt={1}
                    width="100%"
                  >
                    {/* Only show sender name in group chats, not in DMs */}
                    {chat.type === 'group' && !chat.lastMessage.isDeleted ? (
                      <>
                        <Text as="span" fontWeight="medium" color="gray.700">
                          {chat.lastMessage.sender}:
                        </Text>
                        {' '}
                      </>
                    ) : null}
                    {chat.lastMessage.content}
                    {chat.lastMessage.isDeleted && (
                      <Badge 
                        colorScheme="red" 
                        variant="outline"
                        fontSize="2xs"
                        ml={1}
                      >
                        deleted
                      </Badge>
                    )}
                  </Text>
                )}
                {!chat.lastMessage && (
                  <Text 
                    fontSize="sm" 
                    color="gray.500" 
                    fontStyle="italic"
                    mt={1}
                  >
                    No messages yet
                  </Text>
                )}
              </VStack>
              {unreadCount > 0 && (
                <Flex
                  borderRadius="full"
                  bg="green.500"
                  color="white"
                  px={2}
                  py={1}
                  minW="20px"
                  h="20px"
                  alignItems="center"
                  justifyContent="center"
                  fontSize="xs"
                  fontWeight="bold"
                  boxShadow="0px 1px 3px rgba(0, 0, 0, 0.2)"
                  ml={1}
                  transform="translateY(-2px)"
                >
                  {unreadCount}
                </Flex>
              )}
            </HStack>
          </Box>
        );
      })}
    </VStack>
  );

  // Chat detail component
  const ChatDetail = () => {
    const chatContainerRef = useRef(null);
    const isScrolledUpRef = useRef(false);

    // Check if user has scrolled up
    const checkIfScrolledUp = useCallback(() => {
      if (chatContainerRef.current) {
        const { scrollTop, scrollHeight, clientHeight } = chatContainerRef.current;
        isScrolledUpRef.current = scrollHeight - (scrollTop + clientHeight) > 100;
      }
    }, []);

    // Add scroll listener
    useEffect(() => {
      const container = chatContainerRef.current;
      if (container) {
        container.addEventListener('scroll', checkIfScrolledUp);
        return () => container.removeEventListener('scroll', checkIfScrolledUp);
      }
    }, [checkIfScrolledUp]);

    // Smart scroll behavior
    const scrollToBottom = useCallback((behavior = 'smooth') => {
      if (!isScrolledUpRef.current) {
        messagesEndRef.current?.scrollIntoView({ behavior });
      }
    }, []);

    // Scroll on new messages or chat change
    useEffect(() => {
      if (activeChat && chatMessages[activeChat]) {
        const messages = chatMessages[activeChat];
        const lastMessage = messages[messages.length - 1];
        
        // Only scroll if it's a new message (not when typing)
        if (lastMessage && lastMessage.sender) {
          scrollToBottom();
        }
      }
    }, [activeChat, chatMessages, scrollToBottom]);

    // Initial scroll when changing chats
    useEffect(() => {
      if (activeChat) {
        scrollToBottom('auto');
      }
    }, [activeChat, scrollToBottom]);

    // Move all hooks to the top level
    const handleInputChange = useCallback((e) => {
      setMessage(e.target.value);
    }, []);

    const handleKeyDown = useCallback((e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (message.trim() && activeChat) {
          sendMessage(message, activeChat);
        }
      }
    }, [sendMessage, message, activeChat]);

    const handleSendClick = () => {
      if (!message.trim()) return;
      
      if (activeChat) {
        sendMessage(message, activeChat);
      }
    };

    // Focus input on mount and when active chat changes
    useEffect(() => {
      if (activeChat && messageInputRef.current) {
        messageInputRef.current.focus();
      }
    }, [activeChat]);

    if (!activeChat) {
      return (
        <Box h="100%" display="flex" alignItems="center" justifyContent="center">
          <VStack spacing={4}>
            <Text fontSize="xl" color="gray.500">Select a chat or create a new one</Text>
            <Button leftIcon={<AddIcon />} onClick={onNewChatOpen}>
              New Chat
            </Button>
          </VStack>
        </Box>
      );
    }
    
    const chat = chats.find(c => c._id === activeChat);
    if (!chat) return null;
    
    const chatName = chat.type === 'direct' 
      ? chat.otherParticipants?.[0] || chat.name
      : chat.name;
    
    const messages = chatMessages[activeChat] || [];
    const isOnline = chat.type === 'direct' && onlineUsers.includes(chatName);

    return (
      <Box h="100%" display="flex" flexDirection="column">
        <Flex 
          p={4} 
          bg="white" 
          borderBottomWidth={1} 
          alignItems="center"
          justifyContent="space-between"
        >
          <HStack>
            <Avatar 
              name={chatName} 
              bg={isOnline ? "green.500" : "gray.400"}
              cursor={chat.type === 'direct' ? "pointer" : "default"}
              onClick={() => {
                if (chat.type === 'direct') {
                  openUserProfile(chatName);
                }
              }}
              // Add src prop to display user avatar
              src={chat.type === 'direct' ? availableUsers.find(u => u.username === chatName)?.avatar : chat.avatar}
            />
            <VStack spacing={0} align="start">
              <Text 
                fontWeight="bold"
                cursor={chat.type === 'direct' ? "pointer" : "default"}
                onClick={() => {
                  if (chat.type === 'direct') {
                    openUserProfile(chatName);
                  }
                }}
              >
                {chatName}
              </Text>
              <Text fontSize="sm" color="gray.500">
                {isOnline ? 'Online' : chat.type === 'group' ? `${chat.participants.length} members` : 'Offline'}
              </Text>
            </VStack>
          </HStack>
          
          <Menu>
            <MenuButton
              as={IconButton}
              icon={<SettingsIcon />}
              variant="ghost"
              aria-label="Chat options"
            />
            <MenuList>
              {chat.type === 'group' && (
                <MenuItem onClick={() => handleViewMembers(chat._id)}>
                  View Members
                </MenuItem>
              )}
              <MenuItem 
                onClick={() => {
                  if (window.confirm('Are you sure you want to clear all messages? This cannot be undone.')) {
                    handleClearChat(chat._id);
                  }
                }}
              >
                Clear Chat
              </MenuItem>
              <MenuItem 
                color="red.500"
                onClick={() => {
                  if (window.confirm('Are you sure you want to delete this chat? This cannot be undone.')) {
                    handleDeleteChat(chat._id);
                  }
                }}
              >
                Delete Chat
              </MenuItem>
            </MenuList>
          </Menu>
        </Flex>
        
        <VStack 
          ref={chatContainerRef}
          spacing={4} 
          p={4} 
          overflowY="auto" 
          flex={1}
          bg="gray.50"
          align="stretch"
          css={{
            '&::-webkit-scrollbar': {
              width: '8px',
            },
            '&::-webkit-scrollbar-track': {
              background: '#f1f1f1',
            },
            '&::-webkit-scrollbar-thumb': {
              background: '#888',
              borderRadius: '4px',
            },
            '&::-webkit-scrollbar-thumb:hover': {
              background: '#555',
            },
          }}
        >
          {messages.length === 0 ? (
            <Box textAlign="center" my={10}>
              <Text color="gray.500">No messages yet</Text>
            </Box>
          ) : (
            messages.map((msg, index) => (
              <Message key={msg._id || `${msg.timestamp}-${index}`} message={msg} isOwnMessage={msg.sender === user?.username} />
            ))
          )}
          <div ref={messagesEndRef} style={{ height: '1px', width: '100%' }} />
        </VStack>
        
        <Flex 
          p={4} 
          bg="white" 
          borderTopWidth={1} 
          position="relative"
          direction="column"
        >
          {uploadProgress > 0 && (
            <Progress 
              value={uploadProgress} 
              size="xs" 
              colorScheme="blue" 
              position="absolute" 
              top={0} 
              left={0} 
              right={0} 
            />
          )}
          
          <Input
            type="file"
            ref={fileInputRef}
            display="none"
            onChange={(e) => {
              if (e.target.files?.[0]) {
                handleFileUpload(e.target.files[0]);
              }
              e.target.value = ''; // Reset input
            }}
            accept="image/*,.pdf,.doc,.docx"
          />
          
          {typingUsers[activeChat]?.size > 0 && (
            <Text
              fontSize="sm"
              color="gray.500"
              mb={2}
            >
              {Array.from(typingUsers[activeChat]).join(', ')} {
                typingUsers[activeChat].size === 1 ? 'is' : 'are'
              } typing...
            </Text>
          )}
          
          <HStack spacing={2}>
            <IconButton
              icon={<AttachmentIcon />}
              onClick={() => fileInputRef.current?.click()}
              aria-label="Attach file"
              variant="ghost"
            />
            <Input
              ref={messageInputRef}
              value={message}
              onChange={(e) => {
                setMessage(e.target.value);
                if (activeChat) {
                  handleTyping(activeChat);
                }
              }}
              onKeyDown={handleKeyDown}
              placeholder="Type your message..."
              size="md"
              autoComplete="off"
            />
            <Button
              colorScheme="blue"
              onClick={handleSendClick}
              isDisabled={!message.trim()}
              rightIcon={<FaPaperPlane />}
            >
              Send
            </Button>
          </HStack>
        </Flex>
      </Box>
    );
  };

  // New Chat Drawer
  const NewChatDrawer = () => {
    // Use local state for the drawer
    const [localGroupName, setLocalGroupName] = useState(groupName);
    const [localSelectedUser, setLocalSelectedUser] = useState(selectedUser);
    const [localSelectedMembers, setLocalSelectedMembers] = useState(selectedGroupMembers);
    const [activeTab, setActiveTab] = useState(0);

    // Reset local state when drawer opens
    useEffect(() => {
      if (isNewChatOpen) {
        setLocalGroupName(groupName);
        setLocalSelectedUser(selectedUser);
        setLocalSelectedMembers(selectedGroupMembers);
      }
    }, [isNewChatOpen, groupName, selectedUser, selectedGroupMembers]);

    const handleGroupNameChange = (e) => {
      setLocalGroupName(e.target.value);
    };

    const handleUserSelect = (e) => {
      setLocalSelectedUser(e.target.value);
    };

    const handleGroupMemberToggle = (username) => {
      setLocalSelectedMembers(prev => 
        prev.includes(username)
          ? prev.filter(u => u !== username)
          : [...prev, username]
      );
    };

    const handleCreateGroup = (e) => {
      e.preventDefault();
      setGroupName(localGroupName);
      setSelectedGroupMembers(localSelectedMembers);
      handleCreateGroupChat();
    };

    const handleCreateDirect = (e) => {
      e.preventDefault();
      setSelectedUser(localSelectedUser);
      handleCreateDirectChat();
    };

    const handleClose = () => {
      // Reset all states before closing
      setLocalGroupName('');
      setLocalSelectedUser('');
      setLocalSelectedMembers([]);
      setActiveTab(0);
      onNewChatClose();
    };

    return (
      <Drawer
        isOpen={isNewChatOpen}
        placement="right"
        onClose={handleClose}
        size="md"
        closeOnOverlayClick={false}
      >
        <DrawerOverlay />
        <DrawerContent>
          <DrawerCloseButton />
          <DrawerHeader>New Conversation</DrawerHeader>

          <DrawerBody>
            <Tabs 
              isFitted 
              variant="enclosed" 
              index={activeTab}
              onChange={setActiveTab}
            >
              <TabList mb="1em">
                <Tab>Direct Message</Tab>
                <Tab>Create Group</Tab>
              </TabList>
              <TabPanels>
                <TabPanel>
                  <VStack spacing={4} as="form" onSubmit={handleCreateDirect}>
                    <FormControl>
                      <FormLabel>Select User</FormLabel>
                      <Select 
                        placeholder="Select user" 
                        value={localSelectedUser} 
                        onChange={handleUserSelect}
                        isRequired
                      >
                        {availableUsers
                          .filter(u => u.username !== user?.username)
                          .map(u => (
                            <option key={u.username} value={u.username}>
                              {u.username}
                            </option>
                          ))
                        }
                      </Select>
                    </FormControl>
                    <Button 
                      type="submit"
                      colorScheme="blue" 
                      isDisabled={!localSelectedUser}
                      width="full"
                    >
                      Start Conversation
                    </Button>
                  </VStack>
                </TabPanel>
                <TabPanel>
                  <VStack spacing={4} as="form" onSubmit={handleCreateGroup}>
                    <FormControl>
                      <FormLabel>Group Name</FormLabel>
                      <Input 
                        placeholder="Enter group name" 
                        value={localGroupName} 
                        onChange={handleGroupNameChange}
                        autoComplete="off"
                        isRequired
                      />
                    </FormControl>
                    <FormControl>
                      <FormLabel>Select Members</FormLabel>
                      <VStack align="stretch" maxH="200px" overflowY="auto" spacing={2} border="1px" borderColor="gray.200" borderRadius="md" p={2}>
                        {availableUsers
                          .filter(u => u.username !== user?.username)
                          .map(u => (
                            <Flex 
                              key={u.username} 
                              justify="space-between" 
                              align="center"
                              p={2}
                              borderRadius="md"
                              bg={localSelectedMembers.includes(u.username) ? "blue.100" : "white"}
                              cursor="pointer"
                              onClick={() => handleGroupMemberToggle(u.username)}
                              _hover={{ bg: localSelectedMembers.includes(u.username) ? "blue.200" : "gray.100" }}
                            >
                              <HStack>
                                <Avatar name={u.username} size="sm" />
                                <Text>{u.username}</Text>
                              </HStack>
                              <Badge colorScheme={localSelectedMembers.includes(u.username) ? "green" : "gray"}>
                                {localSelectedMembers.includes(u.username) ? "Selected" : ""}
                              </Badge>
                            </Flex>
                          ))
                        }
                      </VStack>
                    </FormControl>
                    <Button 
                      type="submit"
                      colorScheme="blue" 
                      isDisabled={!localGroupName || localSelectedMembers.length === 0}
                      width="full"
                    >
                      Create Group
                    </Button>
                  </VStack>
                </TabPanel>
              </TabPanels>
            </Tabs>
          </DrawerBody>
        </DrawerContent>
      </Drawer>
    );
  };

  // Add ViewMembersDrawer component
  const ViewMembersDrawer = () => {
    return (
      <Drawer
        isOpen={viewMembersOpen}
        placement="right"
        onClose={() => setViewMembersOpen(false)}
        size="md"
      >
        <DrawerOverlay />
        <DrawerContent>
          <DrawerCloseButton />
          <DrawerHeader>Group Members</DrawerHeader>
          <DrawerBody>
            <VStack spacing={4} align="stretch">
              {chatMembers.map(member => (
                <Flex
                  key={member.username}
                  justify="space-between"
                  align="center"
                  p={3}
                  borderWidth={1}
                  borderRadius="md"
                >
                  <HStack>
                    <Avatar name={member.username} size="sm" />
                    <Text>{member.username}</Text>
                  </HStack>
                  <Badge colorScheme={member.isOnline ? "green" : "gray"}>
                    {member.isOnline ? "Online" : "Offline"}
                  </Badge>
                  <Button 
                    size="sm" 
                    onClick={() => {
                      setViewMembersOpen(false);
                      openUserProfile(member.username);
                    }}
                  >
                    View Profile
                  </Button>
                </Flex>
              ))}
            </VStack>
          </DrawerBody>
        </DrawerContent>
      </Drawer>
    );
  };

  // Add handlers for chat options
  const handleViewMembers = useCallback((chatId) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'view_members',
        chatId
      }));
      setViewMembersOpen(true);
    }
  }, []);

  const handleClearChat = useCallback((chatId) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'clear_chat',
        chatId
      }));
    }
  }, []);

  const handleDeleteChat = useCallback((chatId) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'delete_chat',
        chatId
      }));
    }
  }, []);

  // Update the typing handler
  const handleTyping = useCallback((chatId) => {
    if (!ws.current || !user || !chatId) return;

    // Clear any existing timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    // Send typing start
    ws.current.send(JSON.stringify({
      type: 'typing_start',
      chatId: chatId
    }));

    // Set timeout to send typing stop
    typingTimeoutRef.current = setTimeout(() => {
      if (ws.current) {
        ws.current.send(JSON.stringify({
          type: 'typing_stop',
          chatId: chatId
        }));
      }
    }, 2000);
  }, [user]);

  // Add file upload handler
  const handleFileUpload = useCallback(async (file) => {
    if (!file || !activeChat) return;
    
    // Check file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      toast({
        title: 'Error',
        description: 'File size must be less than 10MB',
        status: 'error',
        duration: 3000,
        isClosable: true
      });
      return;
    }
    
    setUploadProgress(1); // Start progress
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      console.log('Starting file upload:', {
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size
      });

      // Use the full server URL
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
      const response = await fetch(`${API_URL}/api/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        body: formData
      });
      
      console.log('Upload response status:', response.status);
      
      // First check if the response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Server returned non-JSON response. Please try again.');
      }
      
      const responseData = await response.json();
      console.log('Upload response:', responseData);
      
      if (!response.ok) {
        throw new Error(responseData.error || 'Upload failed');
      }
      
      // Send file message
      if (ws.current?.readyState === WebSocket.OPEN) {
        const messageData = {
          type: 'chat_message',
          chatId: activeChat,
          content: file.name,
          fileUrl: responseData.fileUrl,
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type
        };
        
        console.log('Sending file message:', messageData);
        ws.current.send(JSON.stringify(messageData));
        
        setUploadProgress(100);
        setTimeout(() => setUploadProgress(0), 1000);
        
        // Removed success toast for file upload
      }
    } catch (error) {
      console.error('File upload error:', error);
      // Only log the error, but don't show a toast notification
      setUploadProgress(0);
    }
  }, [activeChat, accessToken, toast]);

  // Add WebSocket message handler for edits and deletes
  useEffect(() => {
    if (!ws.current) return;

    const handleWebSocketMessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        
        if (data.type === 'message_edited') {
          // Update chat messages
          setChatMessages(prev => {
            const chatMessages = prev[data.chatId] || [];
            return {
              ...prev,
              [data.chatId]: chatMessages.map(msg => 
                msg._id === data.messageId 
                  ? { 
                      ...msg, 
                      content: data.content, 
                      isEdited: true,
                      editedAt: data.editedAt,
                      editHistory: data.editHistory
                    }
                  : msg
              )
            };
          });

          // Update chat list if it was the last message
          setChats(prevChats => 
            prevChats.map(chat => {
              if (chat._id === data.chatId && chat.lastMessage?._id === data.messageId) {
                return {
                  ...chat,
                  lastMessage: {
                    ...chat.lastMessage,
                    content: data.content,
                    isEdited: true,
                    editedAt: data.editedAt
                  }
                };
              }
              return chat;
            })
          );
        }
        
        if (data.type === 'message_deleted') {
          console.log('Message deleted event received directly:', data);
          
          // Update message in chat messages to show as deleted
          setChatMessages(prev => {
            const chatMessages = prev[data.chatId] || [];
            return {
              ...prev,
              [data.chatId]: chatMessages.map(msg => 
                msg._id === data.messageId
                  ? {
                      ...msg,
                      content: 'This message has been deleted',
                      type: 'deleted',
                      isDeleted: true,
                      deletedAt: data.deletedAt
                    }
                  : msg
              )
            };
          });

          // Update chat list if it was the last message
          setChats(prevChats => 
            prevChats.map(chat => {
              if (chat._id === data.chatId && chat.lastMessage?._id === data.messageId) {
                return {
                  ...chat,
                  lastMessage: {
                    ...chat.lastMessage,
                    content: 'This message has been deleted',
                    type: 'deleted',
                    isDeleted: true,
                    deletedAt: data.deletedAt
                  }
                };
              }
              return chat;
            })
          );
          
          // Removed toast notification for message deletion
        }
      } catch (error) {
        console.error('Error handling WebSocket message:', error);
      }
    };

    ws.current.addEventListener('message', handleWebSocketMessage);
    return () => ws.current?.removeEventListener('message', handleWebSocketMessage);
  }, [ws, toast, chats]);

  // Update Message component with better edit and delete handling
  const Message = ({ message, isOwnMessage }) => {
    const [isEditing, setIsEditing] = useState(false);
    const [editedContent, setEditedContent] = useState(message.content);
    const [canEdit, setCanEdit] = useState(false);
    const messageRef = useRef(null);
    const editInputRef = useRef(null);
    const toast = useToast();

    // Reset edited content when message changes
    useEffect(() => {
      setEditedContent(message.content);
    }, [message.content]);

    // Check if message can be edited (within 20 minutes)
    useEffect(() => {
      const checkEditability = () => {
        const messageTime = new Date(message.timestamp).getTime();
        const currentTime = new Date().getTime();
        const timeDiff = currentTime - messageTime;
        const canStillEdit = timeDiff <= 20 * 60 * 1000; // 20 minutes in milliseconds
        setCanEdit(canStillEdit && isOwnMessage && !message.isDeleted);
      };
      
      checkEditability();
      const interval = setInterval(checkEditability, 60000);
      return () => clearInterval(interval);
    }, [message.timestamp, isOwnMessage, message.isDeleted]);

    // Focus input when editing starts
    useEffect(() => {
      if (isEditing && editInputRef.current) {
        editInputRef.current.focus();
      }
    }, [isEditing]);

    const handleEdit = () => {
      if (!canEdit) {
        toast({
          title: "Can't edit message",
          description: "Messages can only be edited within 20 minutes of sending",
          status: 'warning',
          duration: 3000,
          isClosable: true
        });
        return;
      }
      setIsEditing(true);
      setEditedContent(message.content);
    };

    const handleSave = () => {
      if (!canEdit) {
        setIsEditing(false);
        return;
      }

      const trimmedContent = editedContent.trim();
      if (trimmedContent && trimmedContent !== message.content && ws.current?.readyState === WebSocket.OPEN) {
        ws.current.send(JSON.stringify({
          type: 'edit_message',
          messageId: message._id,
          chatId: activeChat,
          content: trimmedContent
        }));
      }
      setIsEditing(false);
    };

    const handleDelete = () => {
      if (window.confirm('Are you sure you want to delete this message?')) {
        if (ws.current?.readyState === WebSocket.OPEN) {
          ws.current.send(JSON.stringify({
            type: 'delete_message',
            messageId: message._id,
            chatId: activeChat
          }));
        }
      }
    };

    const handleKeyDown = (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSave();
      } else if (e.key === 'Escape') {
        setIsEditing(false);
        setEditedContent(message.content);
      }
    };

    // Format the edited time
    const getEditedInfo = () => {
      if (!message.isEdited || !message.editedAt) return null;
      const editedTime = new Date(message.editedAt).toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit' 
      });
      return `edited ${editedTime}`;
    };

    // Get the current chat type to know if this is a DM or group
    const currentChat = chats.find(c => c._id === activeChat);
    const isDirect = currentChat?.type === 'direct';
    
    return (
      <Box
        ref={messageRef}
        role="group"
        position="relative"
        alignSelf={isOwnMessage ? "flex-end" : "flex-start"}
        maxW={{ base: "85%", md: "70%" }}
        mb={2}
      >
        <Box
          bg={isOwnMessage ? "blue.500" : "gray.100"}
          color={isOwnMessage ? "white" : "gray.800"}
          px={4}
          py={3}
          borderRadius="lg"
          borderBottomRightRadius={isOwnMessage ? 0 : "lg"}
          borderBottomLeftRadius={isOwnMessage ? "lg" : 0}
          shadow="sm"
          opacity={message.isDeleted ? 0.7 : 1}
        >
          {/* Only show profile info in group chats, not in DMs */}
          {!isOwnMessage && !isDirect ? (
            <HStack mb={1}>
              <Avatar 
                size="xs" 
                name={message.sender} 
                cursor="pointer" 
                onClick={(e) => {
                  e.stopPropagation();
                  openUserProfile(message.sender);
                }}
                // Look for the user avatar in available users (if loaded)
                src={availableUsers.find(u => u.username === message.sender)?.avatar}
              />
              <Text 
                fontSize="sm" 
                fontWeight="medium" 
                color={isOwnMessage ? "blue.100" : "gray.600"}
                cursor="pointer"
                _hover={{ textDecoration: "underline" }}
                onClick={(e) => {
                  e.stopPropagation();
                  openUserProfile(message.sender);
                }}
              >
                {message.sender}
              </Text>
            </HStack>
          ) : isOwnMessage && !isDirect ? (
            <HStack mb={1} justify="flex-end">
              <Text 
                fontSize="sm" 
                fontWeight="medium" 
                color="blue.100"
                cursor="pointer"
                _hover={{ textDecoration: "underline" }}
                onClick={(e) => {
                  e.stopPropagation();
                  openUserProfile(message.sender);
                }}
              >
                {message.sender}
              </Text>
              <Avatar 
                size="xs" 
                name={message.sender} 
                cursor="pointer" 
                onClick={(e) => {
                  e.stopPropagation();
                  openUserProfile(message.sender);
                }}
                // Use user's avatar for own messages
                src={user?.avatar}
              />
            </HStack>
          ) : null}
          
          {isEditing ? (
            <Textarea
              ref={editInputRef}
              value={editedContent}
              onChange={(e) => setEditedContent(e.target.value)}
              onKeyDown={handleKeyDown}
              autoFocus
              rows={2}
              resize="none"
              bg={isOwnMessage ? "blue.400" : "white"}
              color={isOwnMessage ? "white" : "gray.800"}
              border="none"
              _focus={{
                border: "none",
                boxShadow: "none"
              }}
            />
          ) : (
            <VStack align="start" spacing={1} width="100%">
              <HStack spacing={2} width="100%" align="center">
                {message.type === 'file' ? (
                  <HStack spacing={2}>
                    <AttachmentIcon />
                    {message.fileUrl ? (
                      <Link 
                        href={message.fileUrl} 
                        isExternal 
                        color={isOwnMessage ? "white" : "blue.500"}
                        textDecoration="underline"
                        _hover={{ color: isOwnMessage ? "blue.100" : "blue.700" }}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {message.content || message.fileName || "Attachment"}
                      </Link>
                    ) : (
                      <Text color={isOwnMessage ? "whiteAlpha.800" : "gray.500"}>
                        {message.content || message.fileName || "Attachment"} (URL unavailable)
                      </Text>
                    )}
                  </HStack>
                ) : (
                  <Text 
                    whiteSpace="pre-wrap" 
                    wordBreak="break-word"
                    fontStyle={message.isDeleted ? "italic" : "normal"}
                    color={message.isDeleted ? (isOwnMessage ? "whiteAlpha.800" : "gray.500") : "inherit"}
                  >
                    {message.content}
                  </Text>
                )}
                {message.isDeleted && (
                  <Badge 
                    colorScheme="red" 
                    variant="solid"
                    fontSize="xs"
                    ml={1}
                  >
                    deleted
                  </Badge>
                )}
                {message.isEdited && !message.isDeleted && (
                  <Tooltip 
                    label={getEditedInfo()} 
                    placement="top" 
                    hasArrow
                  >
                    <Badge 
                      colorScheme={isOwnMessage ? "blue" : "gray"}
                      variant="subtle"
                      fontSize="xs"
                    >
                      edited
                    </Badge>
                  </Tooltip>
                )}
              </HStack>
            </VStack>
          )}
        </Box>
        
        {isOwnMessage && !message.isDeleted && message.type !== 'file' && (
          <HStack 
            position="absolute" 
            top={0}
            right="100%"
            px={2}
            opacity={0}
            transition="opacity 0.2s"
            _groupHover={{ opacity: 1 }}
            bg="white"
            borderRadius="md"
            shadow="sm"
          >
            {canEdit && (
              <IconButton
                size="sm"
                variant="ghost"
                icon={isEditing ? <CheckIcon /> : <EditIcon />}
                onClick={isEditing ? handleSave : handleEdit}
                aria-label={isEditing ? "Save edit" : "Edit message"}
              />
            )}
            {!isEditing && (
              <IconButton
                size="sm"
                variant="ghost"
                colorScheme="red"
                icon={<DeleteIcon />}
                onClick={handleDelete}
                aria-label="Delete message"
              />
            )}
          </HStack>
        )}
        
        <Text 
          fontSize="xs" 
          color="gray.500" 
          textAlign={isOwnMessage ? "right" : "left"}
          mt={1}
        >
          {new Date(message.timestamp).toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit' 
          })}
        </Text>
      </Box>
    );
  };

  // Render the connection status indicator
  const ConnectionStatus = () => {
    let color;
    let label;
    
    switch (wsStatus) {
      case 'connected':
        color = 'green.500';
        label = 'Connected';
        break;
      case 'connecting':
        color = 'yellow.500';
        label = 'Connecting...';
        break;
      case 'disconnected':
        color = 'red.500';
        label = 'Disconnected';
        break;
      case 'error':
        color = 'red.700';
        label = 'Error';
        break;
      default:
        color = 'gray.500';
        label = 'Unknown';
    }
    
    return (
      <Tooltip label={label} hasArrow>
        <Box 
          w="10px" 
          h="10px" 
          borderRadius="full" 
          bg={color} 
          display="inline-block"
          ml={2}
        />
      </Tooltip>
    );
  };

  // Use this component in your render to show notifications
  const NotificationsMenu = () => {
    const totalNotifications = notifications.length;
    
    // Create a pulse animation using Chakra's keyframes
    const pulseAnimation = keyframes`
      0% { transform: scale(1); }
      50% { transform: scale(1.2); }
      100% { transform: scale(1); }
    `;
    
    const pulseAnimationStyle = totalNotifications > 0 ? 
      `${pulseAnimation} 2s ease-in-out infinite` : '';
    
    return (
      <Menu>
        <MenuButton
          as={IconButton}
          aria-label="Notifications"
          icon={
            <Box position="relative">
              <BellIcon boxSize={5} />
              {totalNotifications > 0 && (
                <Flex
                  position="absolute"
                  top="-2px"
                  right="-2px"
                  borderRadius="full"
                  bg="green.500"
                  color="white"
                  w="18px"
                  h="18px"
                  fontSize="xs"
                  alignItems="center"
                  justifyContent="center"
                  fontWeight="bold"
                  boxShadow="0px 1px 2px rgba(0, 0, 0, 0.3)"
                  border="2px solid white"
                  animation={pulseAnimationStyle}
                >
                  {totalNotifications}
                </Flex>
              )}
            </Box>
          }
          variant="ghost"
          color="white"
        />
        <MenuList zIndex={1000} maxH="400px" overflowY="auto">
          <MenuItem isDisabled fontWeight="bold">Notifications</MenuItem>
          <MenuItem onClick={() => setNotifications([])} color="blue.500">
            Clear all
          </MenuItem>
          {notifications.length === 0 ? (
            <MenuItem isDisabled>No new notifications</MenuItem>
          ) : (
            notifications.map(notification => (
              <MenuItem 
                key={notification.id}
                onClick={() => {
                  selectChat(notification.chatId);
                  // Remove this notification
                  setNotifications(prev => 
                    prev.filter(n => n.id !== notification.id)
                  );
                }}
              >
                <VStack align="start" spacing={1} w="100%">
                  <HStack w="100%" justify="space-between">
                    <HStack>
                      <Avatar 
                        size="xs" 
                        name={notification.sender}
                        src={availableUsers.find(u => u.username === notification.sender)?.avatar}
                      />
                      <Text fontWeight="bold">{notification.sender}</Text>
                    </HStack>
                    <Text fontSize="xs" color="gray.500">
                      {new Date(notification.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                    </Text>
                  </HStack>
                  <Text noOfLines={1}>{notification.message}</Text>
                </VStack>
              </MenuItem>
            ))
          )}
        </MenuList>
      </Menu>
    );
  };

  // Add a function to open a user's profile
  const openUserProfile = (username) => {
    setProfileUser(username);
    onProfileOpen();
  };

  // User Profile Modal
  const UserProfileModal = () => {
    return (
      <Modal isOpen={isProfileOpen} onClose={onProfileClose} size="xl">
        <ModalOverlay />
        <ModalContent maxW="800px">
          <ModalCloseButton />
          <ModalBody p={0}>
            {profileUser && (
              <UserProfile 
                username={profileUser} 
                accessToken={accessToken} 
                isCurrentUser={profileUser === user?.username}
                onClose={onProfileClose}
              />
            )}
          </ModalBody>
        </ModalContent>
      </Modal>
    );
  };

  // Main layout with auth check
  if (!user) {
    return (
      <ChakraProvider>
        <Box minH="100vh" bg="gray.100" pt={10}>
          <Container maxW="md" centerContent>
            <Box p={8} bg="white" rounded="md" shadow="md" w="100%">
              <AuthForm onLogin={handleLogin} />
            </Box>
          </Container>
        </Box>
      </ChakraProvider>
    );
  }

  return (
    <ChakraProvider>
      <Box minH="100vh" bg="gray.100">
        <Flex 
          p={4} 
          bg="blue.500" 
          color="white" 
          justifyContent="space-between" 
          alignItems="center"
        >
          <HStack>
            <Heading size="md">Chat App</Heading>
            <ConnectionStatus />
          </HStack>
          <HStack spacing={4}>
            <NotificationsMenu />
            
            {/* Total unread messages badge */}
            {user && (
              <Tooltip label="Total unread messages" hasArrow>
                <Badge 
                  colorScheme="green" 
                  borderRadius="full" 
                  p={2} 
                  display="flex"
                  alignItems="center"
                  fontSize="sm"
                  fontWeight="bold"
                  boxShadow="0px 1px 3px rgba(0, 0, 0, 0.2)"
                  border="2px solid white"
                >
                  <HStack spacing={2}>
                    <Text>{Object.values(unreadCounts).reduce((sum, count) => sum + count, 0)}</Text>
                    <Icon as={BellIcon} />
                  </HStack>
                </Badge>
              </Tooltip>
            )}
            
            <Tooltip label={`Online Users: ${onlineUsers.length > 0 ? onlineUsers.join(', ') : 'No other users online'}`} hasArrow>
              <Badge 
                colorScheme="green" 
                borderRadius="full" 
                p={2} 
                display="flex"
                alignItems="center"
              >
                <HStack spacing={2}>
                  <Text>{onlineUsers.length}</Text>
                  <AvatarGroup size="xs" max={3}>
                    {onlineUsers.map((username, i) => (
                      <Avatar 
                        key={username} 
                        name={username} 
                        size="xs"
                        src={availableUsers.find(u => u.username === username)?.avatar}
                      />
                    ))}
                  </AvatarGroup>
                </HStack>
              </Badge>
            </Tooltip>
            
            {/* User profile menu */}
            {user && (
              <Menu>
                <Tooltip label={`Logged in as ${user?.username}`} hasArrow placement="bottom">
                  <MenuButton
                    as={Avatar}
                    size="sm"
                    name={user?.username}
                    cursor="pointer"
                    src={user?.avatar}
                    _hover={{ transform: 'scale(1.1)', transition: 'transform 0.2s' }}
                  />
                </Tooltip>
                <MenuList color="black">
                  <MenuItem closeOnSelect={false}>
                    <VStack align="start" spacing={1} width="100%">
                      <HStack width="100%" justify="space-between">
                        <Avatar 
                          name={user?.username} 
                          size="md" 
                          cursor="pointer"
                          src={user?.avatar}
                          onClick={() => {
                            openUserProfile(user?.username);
                          }}
                        />
                        <VStack align="start" spacing={0}>
                          <Text fontWeight="bold">{user?.username}</Text>
                          <Text fontSize="sm" color="gray.500">Online</Text>
                        </VStack>
                      </HStack>
                    </VStack>
                  </MenuItem>
                  <MenuDivider />
                  <MenuItem 
                    icon={<SettingsIcon />}
                    command="⌘S"
                    onClick={() => openUserProfile(user?.username)}
                  >
                    Profile Settings
                  </MenuItem>
                  <MenuItem 
                    onClick={handleLogout}
                    color="red.500"
                    icon={<Box as="span" fontSize="1.1em">🚪</Box>}
                  >
                    Logout
                  </MenuItem>
                </MenuList>
              </Menu>
            )}
          </HStack>
        </Flex>
        
        <Flex h="calc(100vh - 72px)">
          {/* Left sidebar */}
          <Box 
            w="300px" 
            bg="white" 
            borderRightWidth={1} 
            p={4}
            display="flex"
            flexDirection="column"
          >
            <Flex justifyContent="space-between" alignItems="center" mb={4}>
              <Heading size="md">Chats</Heading>
              <IconButton
                icon={<AddIcon />}
                aria-label="New chat"
                onClick={onNewChatOpen}
                variant="ghost"
              />
            </Flex>
            
            {chats.length === 0 ? (
              <VStack spacing={4} justify="center" h="100%">
                <Text>No chats yet</Text>
                <Button leftIcon={<AddIcon />} onClick={onNewChatOpen}>
                  New Chat
                </Button>
              </VStack>
            ) : (
              <ChatsList />
            )}
          </Box>
          
          {/* Main chat area */}
          <Box flex={1} bg="gray.50">
            <ChatDetail />
          </Box>
        </Flex>
        
        {/* Drawers and Modals */}
        <NewChatDrawer />
        <ViewMembersDrawer />
        <UserProfileModal />
      </Box>
    </ChakraProvider>
  );
};

export default App; 