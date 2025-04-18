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
  AvatarGroup
} from '@chakra-ui/react';
import AuthForm from './components/AuthForm';

const App = () => {
  const [messages, setMessages] = useState([]);
  const [message, setMessage] = useState('');
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const ws = useRef(null);
  const toast = useToast();
  const messagesEndRef = useRef(null);
  const logoutRef = useRef(null);

  const handleLogout = useCallback(async () => {
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
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setAccessToken(null);
      setRefreshToken(null);
      setUser(null);
      setMessages([]);
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      if (ws.current) {
        ws.current.close();
      }
    }
  }, [accessToken, refreshToken, ws]);

  // Update the ref when handleLogout changes
  useEffect(() => {
    logoutRef.current = handleLogout;
  }, [handleLogout]);

  const refreshAccessToken = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:5000/api/refresh-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken }),
      });

      if (!response.ok) {
        throw new Error('Failed to refresh token');
      }

      const data = await response.json();
      setAccessToken(data.accessToken);
      setRefreshToken(data.refreshToken);
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      return data.accessToken;
    } catch (error) {
      console.error('Token refresh error:', error);
      logoutRef.current?.();
      return null;
    }
  }, [refreshToken, logoutRef]);

  const handleLogin = (newAccessToken, newRefreshToken, userData) => {
    console.log('Handling login for user:', userData.username);
    setAccessToken(newAccessToken);
    setRefreshToken(newRefreshToken);
    setUser(userData);
    localStorage.setItem('accessToken', newAccessToken);
    localStorage.setItem('refreshToken', newRefreshToken);
    localStorage.setItem('user', JSON.stringify(userData));
    
    // Clear previous messages on new login
    setMessages([]); 
    setOnlineUsers([]);

    // Ensure existing connection is closed before creating a new one
    if (ws.current && ws.current.readyState !== WebSocket.CLOSED) {
      console.log('Closing existing WebSocket connection before new login.');
      ws.current.close();
    }
    
    // Establish WebSocket connection after state updates
    connectWebSocket(newAccessToken);
  };

  const connectWebSocket = useCallback((token) => {
    if (!token) {
      console.error('No token provided for WebSocket connection');
      return;
    }

    // Prevent multiple connections if one is already open or connecting
    if (ws.current && ws.current.readyState !== WebSocket.CLOSED) {
      console.log('WebSocket connection already exists or is connecting.');
      return;
    }

    console.log('Creating new WebSocket connection with token:', token);
    ws.current = new WebSocket('ws://localhost:5000');

    ws.current.onopen = () => {
      console.log('WebSocket connected, sending login message');
      ws.current.send(JSON.stringify({
        type: 'login',
        token: token
      }));
    };

    ws.current.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
        console.log('Received WebSocket message:', data);
        
        switch (data.type) {
          case 'onlineUsers':
            if (Array.isArray(data.users)) {
              setOnlineUsers(data.users);
            } else {
              console.error('Invalid online users data:', data);
            }
            break;
          case 'message':
            setMessages(prev => [...prev, data]);
            break;
          case 'history':
            if (Array.isArray(data.messages)) {
              console.log('Setting message history:', data.messages.length, 'messages');
              setMessages(data.messages); // Directly set the history
              // Scroll to bottom after history is likely rendered
              setTimeout(() => {
                 messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
              }, 100); 
            } else {
              console.error('Invalid history data format:', data);
            }
            break;
          case 'system':
            setMessages(prev => [...prev, data]);
            break;
          case 'error':
            console.error('WebSocket error message:', data.content);
            if (data.content === 'Invalid or expired token') {
              console.log('Token expired, attempting to refresh...');
              refreshAccessToken().then(newToken => {
                if (newToken && ws.current && ws.current.readyState === WebSocket.OPEN) {
                   console.log('Sending login with refreshed token');
                   ws.current.send(JSON.stringify({
                     type: 'login',
                     token: newToken
                   }));
                } else if (!newToken) {
                   console.log('Refresh token failed, logging out.');
                   logoutRef.current?.(); // Use the ref for logout
                }
              });
            }
            break;
          default:
            console.log('Unknown message type:', data.type);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error, 'Raw data:', event.data);
      }
    };
    
    ws.current.onerror = (error) => {
      console.error('WebSocket error event:', error);
    };
    
    ws.current.onclose = (event) => {
      console.log('WebSocket connection closed. Code:', event.code, 'Reason:', event.reason);
      // Optionally implement automatic reconnection logic here if needed
      // Be cautious to avoid infinite loops, especially on authentication errors
    };
  }, [refreshAccessToken]); // Removed logoutRef from dependencies as it's stable

  // Effect to connect WebSocket when accessToken changes and user is logged in
  useEffect(() => {
    const savedAccessToken = localStorage.getItem('accessToken');
    if (user && savedAccessToken) {
      console.log('User logged in, attempting to connect WebSocket.');
      connectWebSocket(savedAccessToken);
    } else {
      console.log('User not logged in or no token, skipping WebSocket connection.');
    }

    // Cleanup function to close WebSocket on component unmount or when user logs out
    return () => {
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        console.log('Closing WebSocket connection on cleanup.');
        ws.current.close();
      }
    };
  }, [user, connectWebSocket]); // Depend on user and connectWebSocket

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const sendMessage = () => {
    if (message.trim() && ws.current && ws.current.readyState === WebSocket.OPEN) {
      try {
        const messageData = {
          type: 'message',
          content: message.trim()
        };
        console.log('Sending message:', messageData);
        ws.current.send(JSON.stringify(messageData));
        setMessage('');
      } catch (error) {
        console.error('Error sending message:', error);
        toast({
          title: 'Error',
          description: 'Failed to send message',
          status: 'error',
          duration: 3000,
          isClosable: true,
        });
      }
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
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

  if (!user) {
    return (
      <ChakraProvider>
        <Box minH="100vh" bg="gray.100" py={8}>
          <Container maxW="container.sm">
            <AuthForm onLogin={handleLogin} />
          </Container>
        </Box>
      </ChakraProvider>
    );
  }

  return (
    <ChakraProvider>
      <Box minH="100vh" bg="gray.100" py={8}>
        <Container maxW="container.lg">
          <VStack spacing={4} align="stretch">
            <Flex justify="space-between" align="center">
              <VStack align="start" spacing={1}>
                <Text fontSize="2xl" fontWeight="bold">Chat</Text>
                <HStack spacing={2}>
                  <Badge colorScheme="green" fontSize="sm" p={2} borderRadius="md">
                    {onlineUsers.length} {onlineUsers.length === 1 ? 'User' : 'Users'} Online
                  </Badge>
                  <AvatarGroup size="sm" max={5}>
                    {onlineUsers && onlineUsers.map((username, index) => (
                      <Avatar 
                        key={index} 
                        name={username}
                        bg="blue.500"
                        color="white"
                        title={username}
                      />
                    ))}
                  </AvatarGroup>
                </HStack>
              </VStack>
              <Button onClick={handleLogout} colorScheme="red" variant="ghost">
                Logout
              </Button>
            </Flex>

            <Box bg="white" p={6} borderRadius="lg" boxShadow="md">
              <VStack spacing={4} align="stretch" h="60vh" overflowY="auto">
                {messages.map((msg, index) => (
                  <Box
                    key={index}
                    bg={msg.type === 'system' ? 'gray.100' : msg.sender === user?.username ? 'blue.100' : 'gray.100'}
                    p={3}
                    borderRadius="lg"
                    alignSelf={msg.sender === user?.username ? 'flex-end' : 'flex-start'}
                    maxW="70%"
                  >
                    {msg.type === 'system' ? (
                      <Text color="gray.500" fontStyle="italic">{msg.content}</Text>
                    ) : (
                      <>
                        <HStack spacing={2} align="center">
                          <Avatar 
                            size="xs" 
                            name={msg.sender} 
                            bg="blue.500"
                            color="white"
                          />
                          <Text fontSize="sm" fontWeight="bold" color="gray.700">
                            {msg.sender}
                          </Text>
                        </HStack>
                        <Text mt={1}>{msg.content}</Text>
                        <Text fontSize="xs" color="gray.400" mt={1}>
                          {new Date(msg.timestamp).toLocaleString()}
                        </Text>
                      </>
                    )}
                  </Box>
                ))}
                <div ref={messagesEndRef} />
              </VStack>
            </Box>

            <Flex>
              <Input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type your message..."
                onKeyPress={handleKeyPress}
              />
              <Button
                ml={2}
                colorScheme="blue"
                onClick={sendMessage}
                disabled={!message.trim()}
              >
                Send
              </Button>
            </Flex>
          </VStack>
        </Container>
      </Box>
    </ChakraProvider>
  );
};

export default App; 