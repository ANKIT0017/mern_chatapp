import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Button,
  Input,
  VStack,
  HStack,
  Text,
  useToast,
  List,
  ListItem,
  IconButton
} from '@chakra-ui/react';
import { FaPlus, FaSignOutAlt } from 'react-icons/fa';

const RoomManager = ({ isAdmin, currentRoom, onJoinRoom, onLeaveRoom, onLogout, ws }) => {
  const [rooms, setRooms] = useState([]);
  const [newRoomName, setNewRoomName] = useState('');
  const toast = useToast();

  const fetchRooms = useCallback(async () => {
    try {
      console.log('Fetching rooms...');
      const response = await fetch('http://localhost:5000/api/rooms');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      console.log('Rooms fetched:', data);
      setRooms(data.rooms);
    } catch (error) {
      console.error('Error fetching rooms:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch rooms',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
    }
  }, [toast]);

  useEffect(() => {
    fetchRooms();
    const interval = setInterval(fetchRooms, 5000);
    return () => clearInterval(interval);
  }, [fetchRooms]);

  useEffect(() => {
    if (ws) {
      const handleMessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'system' && data.content.includes('has been created by admin')) {
          fetchRooms();
        }
      };
      
      ws.addEventListener('message', handleMessage);
      return () => ws.removeEventListener('message', handleMessage);
    }
  }, [ws, fetchRooms]);

  const handleCreateRoom = () => {
    if (!newRoomName.trim()) return;

    if (!ws) {
      toast({
        title: 'Error',
        description: 'WebSocket connection is not available',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    if (ws.readyState !== WebSocket.OPEN) {
      toast({
        title: 'Error',
        description: 'WebSocket connection is not ready. Please try again in a moment.',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    try {
      ws.send(JSON.stringify({
        type: 'create_room',
        roomName: newRoomName.trim()
      }));
      setNewRoomName('');
      toast({
        title: 'Room creation requested',
        status: 'info',
        duration: 3000,
        isClosable: true,
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to send room creation request',
        status: 'error',
        duration: 3000,
        isClosable: true,
      });
    }
  };

  return (
    <Box p={4} borderWidth={1} borderRadius={8} boxShadow="md">
      <VStack spacing={4} align="stretch">
        <HStack justify="space-between">
          <Text fontSize="xl" fontWeight="bold">Chat Rooms</Text>
          <IconButton
            icon={<FaSignOutAlt />}
            onClick={onLogout}
            aria-label="Logout"
            colorScheme="red"
            variant="ghost"
          />
        </HStack>

        {isAdmin && (
          <HStack>
            <Input
              value={newRoomName}
              onChange={(e) => setNewRoomName(e.target.value)}
              placeholder="New room name"
            />
            <IconButton
              icon={<FaPlus />}
              onClick={handleCreateRoom}
              aria-label="Create room"
              colorScheme="blue"
            />
          </HStack>
        )}

        <List spacing={2}>
          {rooms.map((room) => (
            <ListItem key={room}>
              <Button
                width="full"
                variant={currentRoom === room ? 'solid' : 'outline'}
                colorScheme="blue"
                onClick={() => currentRoom === room ? onLeaveRoom() : onJoinRoom(room)}
              >
                {room}
              </Button>
            </ListItem>
          ))}
        </List>
      </VStack>
    </Box>
  );
};

export default RoomManager; 