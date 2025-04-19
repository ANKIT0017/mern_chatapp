import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Avatar,
  Text,
  VStack,
  Heading,
  Button,
  useToast,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  Badge,
  HStack,
  Divider,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Flex,
  Icon,
  Spinner,
  Tooltip,
  Grid,
  GridItem
} from '@chakra-ui/react';
import { EditIcon, CheckIcon, CloseIcon, TimeIcon } from '@chakra-ui/icons';
import formatDistanceToNow from 'date-fns/formatDistanceToNow';

const UserProfile = ({ 
  username, 
  accessToken, 
  isCurrentUser = false, 
  onClose 
}) => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState({
    bio: '',
    email: '',
    displayName: ''
  });
  const avatarInputRef = useRef(null);
  const { isOpen, onOpen, onClose: onModalClose } = useDisclosure();
  const toast = useToast();
  const [avatarUploading, setAvatarUploading] = useState(false);

  // Fetch profile data
  useEffect(() => {
    const fetchProfile = async () => {
      setLoading(true);
      try {
        const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
        const response = await fetch(`${API_URL}/api/users/${username}/profile`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch profile');
        }
        
        const data = await response.json();
        setProfile(data.profile);
        setFormData({
          bio: data.profile.bio || '',
          email: data.profile.email || '',
          displayName: data.profile.displayName || ''
        });
      } catch (err) {
        console.error('Error fetching profile:', err);
        setError(err.message);
        toast({
          title: 'Error',
          description: 'Failed to load user profile',
          status: 'error',
          duration: 3000,
          isClosable: true
        });
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [username, accessToken, toast]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleAvatarClick = () => {
    if (isCurrentUser) {
      avatarInputRef.current?.click();
    }
  };

  const handleAvatarChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setAvatarUploading(true);
    
    try {
      const formData = new FormData();
      formData.append('avatar', file);
      
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
      const response = await fetch(`${API_URL}/api/users/${username}/avatar`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        body: formData
      });
      
      if (!response.ok) {
        throw new Error('Failed to upload avatar');
      }
      
      const data = await response.json();
      
      // Update profile with new avatar URL - fix to use the correct property from response
      setProfile(prev => ({
        ...prev,
        avatar: data.avatarUrl // Changed from data.avatar to data.avatarUrl to match server response
      }));
      
      toast({
        title: 'Success',
        description: 'Profile picture updated successfully',
        status: 'success',
        duration: 3000,
        isClosable: true
      });
    } catch (err) {
      console.error('Error uploading avatar:', err);
      toast({
        title: 'Error',
        description: 'Failed to update profile picture',
        status: 'error',
        duration: 3000,
        isClosable: true
      });
    } finally {
      setAvatarUploading(false);
      e.target.value = ''; // Reset input
    }
  };

  const handleSaveProfile = async () => {
    try {
      const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
      const response = await fetch(`${API_URL}/api/users/${username}/profile`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });
      
      if (!response.ok) {
        throw new Error('Failed to update profile');
      }
      
      const data = await response.json();
      
      // Update profile with new data
      setProfile(prev => ({
        ...prev,
        ...data.profile
      }));
      
      setEditMode(false);
      
      toast({
        title: 'Success',
        description: 'Profile updated successfully',
        status: 'success',
        duration: 3000,
        isClosable: true
      });
    } catch (err) {
      console.error('Error updating profile:', err);
      toast({
        title: 'Error',
        description: 'Failed to update profile',
        status: 'error',
        duration: 3000,
        isClosable: true
      });
    }
  };

  const handleCancelEdit = () => {
    // Reset form data to current profile values
    setFormData({
      bio: profile?.bio || '',
      email: profile?.email || '',
      displayName: profile?.displayName || ''
    });
    setEditMode(false);
  };

  const formatLastSeen = (date) => {
    if (!date) return 'Unknown';
    return formatDistanceToNow(new Date(date), { addSuffix: true });
  };

  if (loading) {
    return (
      <Box p={5} display="flex" justifyContent="center" alignItems="center" minH="300px">
        <Spinner size="xl" color="blue.500" />
      </Box>
    );
  }

  if (error) {
    return (
      <Box p={5} textAlign="center">
        <Text color="red.500">Error loading profile. Please try again.</Text>
        <Button mt={4} onClick={onClose}>Close</Button>
      </Box>
    );
  }

  return (
    <Box p={5}>
      <VStack spacing={6} align="stretch">
        {/* Profile Header */}
        <Flex direction={{ base: 'column', md: 'row' }} align="center" gap={6}>
          <Box position="relative">
            {avatarUploading ? (
              <Box 
                position="relative" 
                w="150px" 
                h="150px" 
                borderRadius="full" 
                display="flex" 
                justifyContent="center" 
                alignItems="center"
                bg="gray.100"
              >
                <Spinner size="lg" />
              </Box>
            ) : (
              <Avatar 
                size="2xl" 
                name={profile?.displayName || profile?.username} 
                src={profile?.avatar}
                cursor={isCurrentUser ? 'pointer' : 'default'}
                onClick={handleAvatarClick}
              />
            )}
            {isCurrentUser && (
              <Tooltip label="Change profile picture">
                <Box 
                  position="absolute" 
                  bottom="0" 
                  right="0"
                  bg="blue.500"
                  color="white"
                  borderRadius="full"
                  p={2}
                  cursor="pointer"
                  onClick={handleAvatarClick}
                >
                  <EditIcon boxSize={4} />
                </Box>
              </Tooltip>
            )}
            <Input 
              type="file" 
              ref={avatarInputRef} 
              display="none" 
              accept="image/*"
              onChange={handleAvatarChange}
            />
          </Box>
          
          <VStack align="start" flex="1" spacing={2}>
            <Heading size="lg">
              {editMode ? (
                <Input 
                  name="displayName"
                  value={formData.displayName || ''}
                  placeholder="Display Name"
                  onChange={handleInputChange}
                />
              ) : (
                profile?.displayName || profile?.username
              )}
            </Heading>
            
            <HStack>
              <Text fontSize="md" color="gray.600">@{profile?.username}</Text>
              {profile?.isOnline ? (
                <Badge colorScheme="green">Online</Badge>
              ) : (
                <HStack>
                  <TimeIcon color="gray.500" />
                  <Text fontSize="sm" color="gray.500">
                    Last seen {formatLastSeen(profile?.lastSeen)}
                  </Text>
                </HStack>
              )}
            </HStack>
            
            <Text fontSize="sm" color="gray.500">
              Member since {new Date(profile?.createdAt).toLocaleDateString()}
            </Text>
            
            {isCurrentUser && !editMode && (
              <Button 
                leftIcon={<EditIcon />} 
                size="sm" 
                onClick={() => setEditMode(true)}
                mt={2}
              >
                Edit Profile
              </Button>
            )}
          </VStack>
        </Flex>
        
        <Divider />
        
        {/* Profile Body */}
        <Grid 
          templateColumns={{ base: '1fr', md: 'repeat(3, 1fr)' }}
          gap={6}
        >
          {/* Bio Section */}
          <GridItem colSpan={{ base: 1, md: 2 }}>
            <Box>
              <Heading size="md" mb={4}>Bio</Heading>
              {editMode ? (
                <Textarea
                  name="bio"
                  value={formData.bio}
                  placeholder="Write something about yourself..."
                  onChange={handleInputChange}
                  rows={5}
                />
              ) : (
                <Text whiteSpace="pre-wrap">
                  {profile?.bio || 'No bio provided.'}
                </Text>
              )}
            </Box>
            
            {editMode && (
              <Box mt={4}>
                <Heading size="md" mb={4}>Email</Heading>
                <Input
                  name="email"
                  value={formData.email}
                  placeholder="Email address"
                  onChange={handleInputChange}
                />
              </Box>
            )}
            
            {!editMode && profile?.email && (
              <Box mt={6}>
                <Heading size="md" mb={4}>Contact</Heading>
                <Text>{profile.email}</Text>
              </Box>
            )}
          </GridItem>
          
          {/* Common Groups - only show for other users, not own profile */}
          {!isCurrentUser && (
            <GridItem colSpan={1}>
              <Heading size="md" mb={4}>Common Groups</Heading>
              {profile?.commonGroups?.length > 0 ? (
                <VStack align="stretch" spacing={3}>
                  {profile.commonGroups.map(group => (
                    <HStack key={group._id} p={2} bg="gray.50" borderRadius="md">
                      <Avatar size="sm" name={group.name} src={group.avatar} />
                      <Text>{group.name}</Text>
                    </HStack>
                  ))}
                </VStack>
              ) : (
                <Text color="gray.500">No common groups</Text>
              )}
            </GridItem>
          )}
        </Grid>
        
        {/* Edit Mode Buttons */}
        {editMode && (
          <HStack justifyContent="flex-end" mt={4} spacing={3}>
            <Button 
              leftIcon={<CloseIcon />} 
              variant="outline" 
              onClick={handleCancelEdit}
            >
              Cancel
            </Button>
            <Button 
              leftIcon={<CheckIcon />} 
              colorScheme="blue" 
              onClick={handleSaveProfile}
            >
              Save Changes
            </Button>
          </HStack>
        )}
        
        {/* Close button at bottom */}
        {!editMode && (
          <Box textAlign="center" mt={4}>
            <Button onClick={onClose}>Close</Button>
          </Box>
        )}
      </VStack>
    </Box>
  );
};

export default UserProfile; 