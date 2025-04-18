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
  Checkbox,
  List,
  ListItem,
  ListIcon,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription
} from '@chakra-ui/react';
import { CheckCircleIcon, WarningIcon } from '@chakra-ui/icons';

const AuthForm = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [errors, setErrors] = useState([]);
  const toast = useToast();

  const validatePassword = (pass) => {
    const requirements = {
      length: pass.length >= 8,
      uppercase: /[A-Z]/.test(pass),
      lowercase: /[a-z]/.test(pass),
      number: /[0-9]/.test(pass),
      special: /[@$!%*?&]/.test(pass)
    };
    return requirements;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrors([]);

    if (!isLogin) {
      const passwordValidation = validatePassword(password);
      if (!Object.values(passwordValidation).every(Boolean)) {
        setErrors(['Password does not meet requirements']);
        return;
      }
    }

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
        if (data.errors) {
          setErrors(data.errors.map(err => err.msg));
        } else {
          throw new Error(data.error || 'Authentication failed');
        }
        return;
      }

      if (isLogin) {
        onLogin(data.accessToken, data.refreshToken, data.user);
      } else {
        toast({
          title: 'Registration successful',
          description: 'You can now login with your credentials',
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

  const passwordValidation = validatePassword(password);

  return (
    <Box p={8} maxWidth="400px" borderWidth={1} borderRadius={8} boxShadow="lg">
      <VStack spacing={4} align="stretch">
        <Heading textAlign="center">{isLogin ? 'Login' : 'Register'}</Heading>
        {errors.length > 0 && (
          <Alert status="error">
            <AlertIcon />
            <Box>
              <AlertTitle>Registration Error</AlertTitle>
              <AlertDescription>
                {errors.map((error, index) => (
                  <Text key={index}>{error}</Text>
                ))}
              </AlertDescription>
            </Box>
          </Alert>
        )}
        <form onSubmit={handleSubmit}>
          <VStack spacing={4}>
            <FormControl isRequired>
              <FormLabel>Username</FormLabel>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username (3-20 characters)"
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
              {!isLogin && (
                <List spacing={1} mt={2}>
                  <ListItem>
                    <ListIcon as={passwordValidation.length ? CheckCircleIcon : WarningIcon} color={passwordValidation.length ? 'green.500' : 'gray.500'} />
                    At least 8 characters
                  </ListItem>
                  <ListItem>
                    <ListIcon as={passwordValidation.uppercase ? CheckCircleIcon : WarningIcon} color={passwordValidation.uppercase ? 'green.500' : 'gray.500'} />
                    At least one uppercase letter
                  </ListItem>
                  <ListItem>
                    <ListIcon as={passwordValidation.lowercase ? CheckCircleIcon : WarningIcon} color={passwordValidation.lowercase ? 'green.500' : 'gray.500'} />
                    At least one lowercase letter
                  </ListItem>
                  <ListItem>
                    <ListIcon as={passwordValidation.number ? CheckCircleIcon : WarningIcon} color={passwordValidation.number ? 'green.500' : 'gray.500'} />
                    At least one number
                  </ListItem>
                  <ListItem>
                    <ListIcon as={passwordValidation.special ? CheckCircleIcon : WarningIcon} color={passwordValidation.special ? 'green.500' : 'gray.500'} />
                    At least one special character (@$!%*?&)
                  </ListItem>
                </List>
              )}
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
            onClick={() => {
              setIsLogin(!isLogin);
              setErrors([]);
            }}
          >
            {isLogin ? 'Register' : 'Login'}
          </Button>
        </Text>
      </VStack>
    </Box>
  );
};

export default AuthForm; 