// ChatList.jsx

import React, { useState, useEffect, useContext } from 'react';
import axios from 'axios';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBars } from '@fortawesome/free-solid-svg-icons';
import Modal from './Modal';
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext';


function ChatList({ onLobbySelect, onUserSelect }) {
    const [conversations, setConversations] = useState([]);
    const [showMenu, setShowMenu] = useState(false);
    const [showDmModal, setShowDmModal] = useState(false);
    const [recipientNickname, setRecipientNickname] = useState('');
    const [message, setMessage] = useState('');
    const { logout } = useAuth();
    const navigate = useNavigate();
    const localToken = localStorage.getItem('token')
  

    useEffect(() => {
        if(localToken) {
            fetchConversations();
            console.log("hello token")
        } else {
            alert("prob with token")
        }
        
    }, [localToken]);


    const fetchConversations = async () => {
        try {
            const lobbiesResponse = await axios.get('/api/user/lobbies', {
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const lobbies = lobbiesResponse.data;
            console.log(lobbies);
            const dmResponse = await axios.get('/api/direct-messages', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const dms = dmResponse.data.sent.concat(dmResponse.data.received).map((dm, index) => {
                const partnerId = dm.sender_id === parseInt(dmResponse.config.userId) ? dm.receiver_id : dm.sender_id;
                const partnerNickname = dm.sender_id === parseInt(dmResponse.config.userId) ? dm.receiver_nickname : dm.sender_nickname;
                return {
                    id: `dm-${dm.id}-${partnerId}-${index}`,  // adding index to ensure uniqueness
                    name: `DM with ${partnerNickname}`,
                    type: 'dm',
                    partnerName: partnerNickname
                };
            }); 

            // Combine lobbies and DMs into a single list with unique keys
            setConversations([...lobbies, ...dms]);
        } catch (error) {
            console.error('Failed to fetch conversations:', error);
            setConversations([]);
        }
    };


    const handleCreateLobby = async () => {
        const lobbyName = prompt("Please enter the name for the new lobby:");
        if (!lobbyName) return;

        try {
            const response = await axios.post('/api/create-lobby', { lobbyName }, {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            
            fetchConversations();  
        } catch (error) {
            console.error('Failed to create lobby:', error);
        }
    };


    const handleSendDM = async () => {
        if (!recipientNickname || !message) {
            alert("Both fields are required!");
            return;
        }
        try {
            const { data: user } = await axios.get(`/api/find-user/${recipientNickname}`, {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });

            const recipientId = user.id;
            if (!recipientId) {
                alert("User not found!");
                return;
            }

            await axios.post('/api/send-direct-message', {
                recipientId,
                message
            }, {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });

            alert("Message sent successfully!");
            fetchConversations();
            setShowDmModal(false); // Close modal after sending
        } catch (error) {
            console.error('Error sending direct message:', error);
            alert('Failed to send message.');
        }
    };


    const handleJoinLobby = async () => {
        const lobbyId = prompt("Please enter the Lobby ID you want to join:");
        if (!lobbyId) return;
        try {
            const response = await axios.post(`/api/lobby/${lobbyId}/join`, {}, {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            if (response.status === 200) {
                alert('You have joined the lobby successfully');
                fetchConversations(); 
            }
        } catch (error) {
            console.error('Error joining the lobby:', error);
            alert(error.response?.data?.error || 'Failed to join the lobby');
        }
    };

   /*  const logout = () => {
        localStorage.removeItem("token");
        localStorage.removeItem("userId");
        setUser(null); // Réinitialiser l'état de l'utilisateur
        setIsAdmin(false); // Réinitialiser le statut d'administrateur
        console.log('User logged out successfully');
        navigate('/login');
    } */ 


    return (
        <div className="chat-list">
            <div className="chat-list-header">
                <div className="menu-button" onClick={() => setShowMenu(!showMenu)}>
                    <FontAwesomeIcon icon={faBars} />
                </div>
                <span>Your Conversations</span>
            </div>

            {showMenu && (
                <div className="menu-options">
                    <div onClick={handleCreateLobby}>Create a Lobby</div>
                    <div onClick={handleJoinLobby}>Join a Lobby</div>
                    <div onClick={() => setShowDmModal(true)}>Send a DM</div>
                </div>
            )}

            {conversations.map(conv => (
                <div key={conv.id} className="chat-list-item" onClick={() => conv.type === 'dm' ? onUserSelect(conv.id) : onLobbySelect(conv)}>
                    {conv.name}
                    <div className="chat-preview">{conv.partnerName ? `Last message with ${conv.partnerName}` : "Last message preview here"}</div>
                </div>
            ))}
                <button className="logout-button" onClick={logout}>Logout</button>

                <Modal show={showDmModal} onClose={() => setShowDmModal(false)}>
                    <h2>Send Direct Message</h2>
                    <input
                        type="text"
                        value={recipientNickname}
                        onChange={(e) => setRecipientNickname(e.target.value)}
                        placeholder="Recipient's nickname"
                    />
                    <textarea
                        value={message}
                        onChange={(e) => setMessage(e.target.value)}
                        placeholder="Your message"
                    />
                    <div className="modal-footer"> 
                        <button onClick={handleSendDM}>Send Message</button>
                    </div>
                </Modal>

        </div>
    );
}


export default ChatList;
