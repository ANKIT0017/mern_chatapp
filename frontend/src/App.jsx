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
  useToast
} from '@chakra-ui/react';
import AuthForm from './components/AuthForm';

const App = () => {
  const [messages, setMessages] = useState([]);
  const [message, setMessage] = useState('');
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const ws = useRef(null);
  const toast = useToast();
  const messagesEndRef = useRef(null);

  const connectWebSocket = useCallback(() => {
    try {
      ws.current = new WebSocket('ws://localhost:5000');

      ws.current.onopen = () => {
        console.log('WebSocket connected');
        if (token) {
          ws.current.send(JSON.stringify({
            type: 'login',
            token
          }));
        }
      };

      ws.current.onmessage = (event) => {
        console.log('Message received:', event.data);
        const data = JSON.parse(event.data);
        
        if (data.type === 'error') {
          toast({
            title: 'Error',
            description: data.content,
            status: 'error',
            duration: 3000,
            isClosable: true,
          });
          return;
        }

        setMessages((prev) => [...prev, data]);
      };

      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        toast({
          title: 'Connection Error',
          description: 'Failed to connect to the chat server',
          status: 'error',
          duration: 3000,
          isClosable: true,
        });
      };

      ws.current.onclose = () => {
        console.log('WebSocket disconnected');
        toast({
          title: 'Disconnected',
          description: 'Lost connection to the chat server',
          status: 'error',
          duration: 3000,
          isClosable: true,
        });
      };
    } catch (error) {
      console.error('Error creating WebSocket:', error);
      toast({
        title: 'Connection Error',
        description: 'Failed to create WebSocket connection',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
    }
  }, [token, toast]);

  useEffect(() => {
    if (token) {
      connectWebSocket();
    }
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [token, connectWebSocket]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleLogin = (newToken, userData) => {
    setToken(newToken);
    setUser(userData);
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    setMessages([]);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    if (ws.current) {
      ws.current.close();
    }
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
    const savedToken = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
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
              <Text fontSize="2xl" fontWeight="bold">Chat</Text>
              <Button onClick={handleLogout} colorScheme="red" variant="ghost">
                Logout
              </Button>
            </Flex>

            <Box bg="white" p={6} borderRadius="lg" boxShadow="md">
              <VStack spacing={4} align="stretch" h="60vh" overflowY="auto">
                {messages.map((msg, index) => (
                  <Box
                    key={index}
                    bg={msg.type === 'system' ? 'gray.100' : msg.sender === user.username ? 'blue.100' : 'gray.100'}
                    p={3}
                    borderRadius="lg"
                    alignSelf={msg.sender === user.username ? 'flex-end' : 'flex-start'}
                    maxW="70%"
                  >
                    {msg.type === 'system' ? (
                      <Text color="gray.500" fontStyle="italic">{msg.content}</Text>
                    ) : (
                      <>
                        <Text fontSize="sm" color="gray.500">
                          {msg.sender}
                        </Text>
                        <Text>{msg.content}</Text>
                        <Text fontSize="xs" color="gray.400">
                          {new Date(msg.timestamp).toLocaleTimeString()}
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