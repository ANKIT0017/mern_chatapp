import React, { useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Input,
  VStack,
  Heading,
  Text,
  useToast,
  Checkbox
} from '@chakra-ui/react';

const AuthForm = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const toast = useToast();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`http://localhost:5000/api/${isLogin ? 'login' : 'register'}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
          isAdmin: isLogin ? undefined : isAdmin
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (isLogin) {
        onLogin(data.token, data.user);
      } else {
        toast({
          title: 'Registration successful',
          status: 'success',
          duration: 3000,
          isClosable: true,
        });
        setIsLogin(true);
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error.message,
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
    }
  };

  return (
    <Box p={8} maxWidth="400px" borderWidth={1} borderRadius={8} boxShadow="lg">
      <VStack spacing={4} align="stretch">
        <Heading textAlign="center">{isLogin ? 'Login' : 'Register'}</Heading>
        <form onSubmit={handleSubmit}>
          <VStack spacing={4}>
            <FormControl isRequired>
              <FormLabel>Username</FormLabel>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
              />
            </FormControl>
            <FormControl isRequired>
              <FormLabel>Password</FormLabel>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
              />
            </FormControl>
            {!isLogin && (
              <FormControl>
                <Checkbox
                  isChecked={isAdmin}
                  onChange={(e) => setIsAdmin(e.target.checked)}
                >
                  Register as admin
                </Checkbox>
              </FormControl>
            )}
            <Button type="submit" colorScheme="blue" width="full">
              {isLogin ? 'Login' : 'Register'}
            </Button>
          </VStack>
        </form>
        <Text textAlign="center">
          {isLogin ? "Don't have an account? " : 'Already have an account? '}
          <Button
            variant="link"
            colorScheme="blue"
            onClick={() => setIsLogin(!isLogin)}
          >
            {isLogin ? 'Register' : 'Login'}
          </Button>
        </Text>
      </VStack>
    </Box>
  );
};

export default AuthForm; 