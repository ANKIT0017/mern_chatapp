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
  MenuDivider
} from '@chakra-ui/react';
import { AddIcon, SettingsIcon, BellIcon } from '@chakra-ui/icons';
import AuthForm from './components/AuthForm';

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

  // Drawer state
  const { 
    isOpen: isNewChatOpen, 
    onOpen: onNewChatOpen, 
    onClose: onNewChatClose 
  } = useDisclosure();
  
  // Form states for creating chats
  const [selectedUser, setSelectedUser] = useState('');
  const [groupName, setGroupName] = useState('');
  const [selectedGroupMembers, setSelectedGroupMembers] = useState([]);

  // WebSocket connection management
  const [wsStatus, setWsStatus] = useState('disconnected');
  const MAX_RECONNECT_ATTEMPTS = 1000; // Increased to allow for more reconnection attempts
  const RECONNECT_DELAY = 2000; // Reduced initial delay to 2 seconds
  const MAX_SYSTEM_MESSAGES = 2;
  const PING_INTERVAL = 15000; // Reduced to 15 seconds for more frequent health checks
  const CONNECTION_TIMEOUT = 10000; // Reduced to 10 seconds

  // Add rate limiting for token refresh
  const MIN_REFRESH_INTERVAL = 10000; // Minimum 10 seconds between refreshes

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
        // Verify each message has a valid sender
        const validMessages = data.messages.filter(msg => msg.sender && typeof msg.sender === 'string');
        
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

    // Handle new messages
    if (data.messageData) {
      // Verify the message has a valid sender
      if (!data.messageData.sender || typeof data.messageData.sender !== 'string') {
        console.error('Invalid message sender:', data.messageData);
        return;
      }

      setChatMessages(prev => {
        const chatMessages = prev[data.chatId] || [];
        
        // Check if message already exists
        const isDuplicate = chatMessages.some(msg => 
          (msg._id && msg._id === data.messageData._id) || 
          (msg.sender === data.messageData.sender && 
           msg.timestamp === data.messageData.timestamp && 
           msg.content === data.messageData.content)
        );
        
        if (isDuplicate) {
          return prev;
        }

        return {
          ...prev,
          [data.chatId]: [...chatMessages, data.messageData]
        };
      });

      // Handle unread counts and notifications
      if (data.chatId !== activeChat && data.messageData.sender !== user.username) {
        setUnreadCounts(prev => ({
          ...prev,
          [data.chatId]: (prev[data.chatId] || 0) + 1
        }));
        
        showNotification(
          data.messageData.sender,
          data.messageData.content,
          data.chatId
        );
      }
      
      if (data.chatId === activeChat) {
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
        // Refresh token 1 minute before it expires (assuming 15 min expiry)
        const success = await refreshAccessToken();
        if (!success) {
          console.error('Failed to refresh token');
        }
      }, 14 * 60 * 1000); // 14 minutes

      return () => clearInterval(refreshInterval);
    }
  }, [user, accessToken, refreshAccessToken]);

  // Update handleLogout to ensure proper cleanup
  const handleLogout = useCallback(async () => {
    console.log('Handling logout for user:', user?.username);
    try {
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        ws.current.send(JSON.stringify({
          type: 'logout',
          token: accessToken
        }));
      }

      // Call logout endpoint
      await fetch('http://localhost:5000/api/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({ refreshToken })
      });

      // Clear all stored tokens and user data
      localStorage.clear(); // Clear all stored data
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Reset all state
      setAccessToken(null);
      setRefreshToken(null);
      setUser(null);
      setChats([]);
      setChatMessages({});
      setActiveChat(null);
      setOnlineUsers([]);
      setNotifications([]);
      
      // Close WebSocket connection
      if (ws.current) {
        ws.current.close();
        ws.current = null;
      }

      // Reset all refs
      reconnectAttempts.current = 0;
      lastTokenRefresh.current = 0;
      isRefreshingToken.current = false;
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
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }
    
    reconnectAttempts.current += 1;
    
    // Calculate delay with exponential backoff
    let delay = RECONNECT_DELAY;
    if (forceBackoff || reconnectAttempts.current > 2) {
      delay = Math.min(30000, RECONNECT_DELAY * Math.pow(1.5, Math.min(reconnectAttempts.current - 1, 10)));
    }
    
    console.log(`Scheduling reconnection attempt ${reconnectAttempts.current} in ${delay}ms`);
    setWsStatus('reconnecting');
    
    reconnectTimeout.current = setTimeout(() => {
      if (user && accessToken) {
        console.log(`Attempting reconnection ${reconnectAttempts.current}`);
        if (connectWebSocketRef.current) {
          connectWebSocketRef.current();
        }
      }
    }, delay);
  }, [user, accessToken]);

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
    const socketUrl = `ws://localhost:5000?id=${uniqueId}&reconnect=${reconnectCount}&t=${timestamp}`;
    
    try {
      // Close any existing connection first
      if (ws.current) {
        console.log('Closing existing WebSocket connection before creating a new one.');
        try {
          ws.current.close(1000, "Replaced by new connection");
        } catch (e) {
          console.error('Error closing previous connection:', e);
        }
      }
      
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

      // Update WebSocket message handler
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
              // Remove the current user from the online users list since they're shown separately
              const otherOnlineUsers = uniqueUsers.filter(u => u !== user?.username);
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
            case 'system':
              handleSystemMessage(data);
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
        
        // Only attempt to reconnect if not a normal closure and user is still logged in
        if (event.code !== 1000 && event.code !== 1001 && user) {
          if (document.visibilityState === 'visible') {
            console.log('Abnormal closure, attempting to reconnect...');
            if (handleReconnectRef.current) {
              handleReconnectRef.current(false);
            }
          }
        }
      };
      
      // Handle connection errors
      ws.current.onerror = (error) => {
        console.error('WebSocket error occurred:', error);
        setWsStatus('error');
        
        // Don't try to immediately reconnect on error
        // The onclose handler will be called and will handle reconnection
      };
      
    } catch (error) {
      console.error('Error establishing WebSocket connection:', error);
      setWsStatus('error');
      if (handleReconnectRef.current) {
        handleReconnectRef.current(true);
      }
    }
  }, [accessToken, user, refreshAccessToken]);

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
        
        if (ws.current.readyState === WebSocket.OPEN && inactivityTime > PING_INTERVAL * 2) {
          console.log(`No activity for ${inactivityTime}ms, checking connection...`);
          try {
            ws.current.send(JSON.stringify({ type: 'ping', timestamp: now }));
          } catch (error) {
            console.error('Error sending ping, connection may be dead:', error);
            if (handleReconnectRef.current) {
              handleReconnectRef.current(true);
            }
          }
        } else if (ws.current.readyState !== WebSocket.OPEN && ws.current.readyState !== WebSocket.CONNECTING) {
          console.log('Connection is closed or closing, attempting to reconnect...');
          if (handleReconnectRef.current) {
            handleReconnectRef.current(false);
          }
        }
      } else if (user) {
        console.log('No WebSocket instance found, creating new connection...');
        if (connectWebSocketRef.current) {
          connectWebSocketRef.current();
        }
      }
    };

    const intervalId = setInterval(checkConnection, PING_INTERVAL);
    
    return () => clearInterval(intervalId);
  }, [user]);

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

  const sendMessage = useCallback(() => {
    if (!message.trim() || !activeChat || !ws.current || ws.current.readyState !== WebSocket.OPEN || !user) {
      return;
    }

    const messageContent = message.trim();
    setMessage('');

    const messageData = {
      type: 'chat_message',
      chatId: activeChat,
      content: messageContent,
      token: accessToken // Add token for server-side validation
    };

    try {
      ws.current.send(JSON.stringify(messageData));
    } catch (error) {
      console.error('Error sending message:', error);
      toast({
        title: "Error",
        description: "Failed to send message. Please try again.",
        status: "error",
        duration: 3000,
        isClosable: true,
      });
      setMessage(messageContent);
    }
  }, [message, activeChat, ws, toast, user, accessToken]);

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
      
      // Add optimistic update
      const newGroupChat = {
        _id: `temp-${Date.now()}`,
        type: 'group',
        name: groupName,
        participants: [...selectedGroupMembers, user.username],
        createdBy: user.username,
        lastMessage: null,
        createdAt: new Date().toISOString()
      };
      
      setChats(prevChats => [newGroupChat, ...prevChats]);
      setActiveChat(newGroupChat._id);
      
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
      
      // Add optimistic update
      const newDirectChat = {
        _id: `temp-${Date.now()}`,
        type: 'direct',
        name: `${user.username}_${selectedUser}`,
        participants: [user.username, selectedUser],
        otherParticipants: [selectedUser],
        createdBy: user.username,
        lastMessage: null,
        createdAt: new Date().toISOString()
      };
      
      setChats(prevChats => [newDirectChat, ...prevChats]);
      setActiveChat(newDirectChat._id);
      
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
    <VStack spacing={2} align="stretch" overflowY="auto" h="calc(100vh - 200px)">
      {chats.map((chat) => {
        // For direct chats, show the other person's name
        const chatName = chat.type === 'direct' 
          ? chat.otherParticipants?.[0] || chat.name
          : chat.name;
          
        // Get unread count for this chat
        const unreadCount = unreadCounts[chat._id] || 0;
        
        // Check if user is online
        const isOnline = chat.type === 'direct' && onlineUsers.includes(chatName);
        
        return (
          <Box 
            key={chat._id}
            p={3}
            bg={activeChat === chat._id ? "blue.100" : "white"}
            borderRadius="md"
            cursor="pointer"
            _hover={{ bg: "gray.100" }}
            onClick={() => selectChat(chat._id)}
            position="relative"
          >
            <HStack spacing={3}>
              <Avatar 
                name={chatName} 
                bg={isOnline ? "green.500" : "gray.400"}
              />
              <VStack spacing={0} align="start" flex={1}>
                <Text fontWeight="bold">{chatName}</Text>
                <Text fontSize="sm" color="gray.500" noOfLines={1}>
                  {chat.lastMessage ? (
                    <>
                      {chat.lastMessage.sender}: {chat.lastMessage.content}
                    </>
                  ) : (
                    <Text as="i">No messages yet</Text>
                  )}
                </Text>
              </VStack>
              {chat.lastMessage && (
                <Text fontSize="xs" color="gray.500">
                  {new Date(chat.lastMessage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </Text>
              )}
              {unreadCount > 0 && (
                <Badge 
                  borderRadius="full" 
                  px={2} 
                  colorScheme="green" 
                  position="absolute"
                  right={3}
                  top={3}
                >
                  {unreadCount}
                </Badge>
              )}
            </HStack>
          </Box>
        );
      })}
    </VStack>
  );

  // Chat detail component
  const ChatDetail = () => {
    // Move all hooks to the top level
    const handleInputChange = useCallback((e) => {
      setMessage(e.target.value);
    }, []);

    const handleKeyDown = useCallback((e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    }, [sendMessage]);

    const handleSendClick = useCallback(() => {
      sendMessage();
    }, [sendMessage]);

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
            />
            <VStack spacing={0} align="start">
              <Text fontWeight="bold">{chatName}</Text>
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
          spacing={4} 
          p={4} 
          overflowY="auto" 
          flex={1}
          bg="gray.50"
          align="stretch"
        >
          {messages.length === 0 ? (
            <Box textAlign="center" my={10}>
              <Text color="gray.500">No messages yet</Text>
            </Box>
          ) : (
            messages.map((msg, index) => (
              <Box
                key={msg._id || `${msg.timestamp}-${index}`}
                bg={msg.sender === user?.username ? "blue.100" : "white"}
                p={3}
                borderRadius="lg"
                alignSelf={msg.sender === user?.username ? "flex-end" : "flex-start"}
                maxW="70%"
                boxShadow="sm"
              >
                {msg.sender !== user?.username && (
                  <Text fontSize="xs" fontWeight="bold" color="gray.500" mb={1}>
                    {msg.sender}
                  </Text>
                )}
                <Text wordBreak="break-word">{msg.content}</Text>
                <Text fontSize="xs" color="gray.500" textAlign="right" mt={1}>
                  {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </Text>
              </Box>
            ))
          )}
          <div ref={messagesEndRef} />
        </VStack>
        
        <Flex p={4} bg="white" borderTopWidth={1}>
          <Input
            ref={messageInputRef}
            value={message}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder="Type your message..."
            mr={2}
            size="md"
            autoComplete="off"
          />
          <Button
            colorScheme="blue"
            onClick={handleSendClick}
            isDisabled={!message.trim()}
          >
            Send
          </Button>
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
    const notificationsRef = useRef(null);
    
    return (
      <Menu>
        <MenuButton
          as={IconButton}
          aria-label="Notifications"
          icon={
            <Box position="relative">
              <BellIcon />
              {notifications.length > 0 && (
                <Badge 
                  colorScheme="red" 
                  position="absolute" 
                  top="-8px" 
                  right="-8px"
                  borderRadius="full"
                  fontSize="xs"
                >
                  {notifications.length}
                </Badge>
              )}
            </Box>
          }
          variant="ghost"
          color="white"
        />
        <MenuList zIndex={1000} maxH="400px" overflowY="auto" ref={notificationsRef}>
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
                    <Text fontWeight="bold">{notification.sender}</Text>
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
          <HStack>
            <NotificationsMenu />
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
                      />
                    ))}
                  </AvatarGroup>
                </HStack>
              </Badge>
            </Tooltip>
            <Menu>
              <Tooltip label={`Logged in as ${user?.username}`} hasArrow placement="bottom">
                <MenuButton
                  as={Avatar}
                  size="sm"
                  name={user?.username}
                  cursor="pointer"
                  _hover={{ transform: 'scale(1.1)', transition: 'transform 0.2s' }}
                />
              </Tooltip>
              <MenuList color="black">
                <MenuItem closeOnSelect={false}>
                  <VStack align="start" spacing={1} width="100%">
                    <HStack width="100%" justify="space-between">
                      <Avatar name={user?.username} size="md" />
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
                >
                  Settings
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
      </Box>
    </ChakraProvider>
  );
};

export default App; 