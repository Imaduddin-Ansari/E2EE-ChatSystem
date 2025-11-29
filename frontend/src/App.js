// =============================================================================
// APP.JS - FIXED VERSION - Proper User Loading
// =============================================================================

import React, { useState, useEffect, useRef } from 'react';
import CryptoUtils from './data/cryptoUtils';
import KeyStorage from './data/keyStorage';
import api from './data/api';
import './App.css';

function App() {
  // ===========================================================================
  // STATE MANAGEMENT
  // ===========================================================================
  
  const [view, setView] = useState('login');
  const [user, setUser] = useState(null);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [files, setFiles] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [sessionKeys, setSessionKeys] = useState({});
  const [securityLogs, setSecurityLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [authForm, setAuthForm] = useState({ username: '', password: '' });
  
  // Cache for storing messages/files per conversation
  const [conversationCache, setConversationCache] = useState({});
  
  const messageSequence = useRef({});
  const fileInputRef = useRef(null);

  // ===========================================================================
  // UTILITY FUNCTIONS
  // ===========================================================================

  const addLog = (type, message) => {
    const log = {
      type,
      message,
      timestamp: new Date().toISOString()
    };
    setSecurityLogs(prev => [log, ...prev].slice(0, 50));
    console.log(`[${type.toUpperCase()}] ${message}`);
  };

  // ===========================================================================
  // USER MANAGEMENT - FIXED
  // ===========================================================================

  const loadUsers = async () => {
    try {
      if (!user || !user.id) {
        console.log('❌ loadUsers called but user is null or has no id');
        return;
      }
      
      console.log('📡 Loading users for user ID:', user.id);
      
      const userList = await api.getUsers(user.id);
      
      console.log('✅ Received users:', userList);
      
      setUsers(userList);
      addLog('info', `Loaded ${userList.length} users`);
    } catch (err) {
      console.error('❌ Failed to load users:', err);
      addLog('error', `Failed to load users: ${err.message}`);
    }
  };

  // ===========================================================================
  // CRITICAL FIX: useEffect to load users when user state changes
  // ===========================================================================
  
  useEffect(() => {
    console.log('🔄 User state changed:', user?.username, 'View:', view);
    
    if (user && view === 'chat') {
      console.log('✅ User is logged in and view is chat - loading users...');
      loadUsers();
    }
  }, [user, view]); // This will run whenever user or view changes

  // ===========================================================================
  // AUTHENTICATION
  // ===========================================================================

  const handleRegister = async () => {
    try {
      setLoading(true);
      setError('');
      
      const { username, password } = authForm;
      
      if (!username || !password) {
        setError('Username and password are required');
        return;
      }

      if (password.length < 8) {
        setError('Password must be at least 8 characters');
        return;
      }

      addLog('info', 'Generating cryptographic key pairs...');
      
      const ecdhKeyPair = await CryptoUtils.generateECDHKeyPair();
      const ecdsaKeyPair = await CryptoUtils.generateECDSAKeyPair();
      
      const ecdhPublicKey = await CryptoUtils.exportPublicKey(ecdhKeyPair.publicKey);
      const ecdsaPublicKey = await CryptoUtils.exportPublicKey(ecdsaKeyPair.publicKey);
      
      addLog('info', 'Registering user with server...');
      
      const response = await api.register({
        username,
        password,
        ecdhPublicKey,
        ecdsaPublicKey
      });
      
      await KeyStorage.saveKeys(response.user.id, ecdhKeyPair, ecdsaKeyPair);
      
      addLog('success', `User ${username} registered successfully`);
      addLog('info', 'Private keys stored securely in IndexedDB');
      
      // Set user and view - useEffect will handle loading users
      setUser(response.user);
      setView('chat');
      // DON'T call loadUsers() here - let useEffect handle it
      
    } catch (err) {
      setError(err.message);
      addLog('error', `Registration failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    try {
      setLoading(true);
      setError('');
      
      const { username, password } = authForm;
      
      if (!username || !password) {
        setError('Username and password are required');
        return;
      }
      
      addLog('info', `Attempting login for user ${username}...`);
      
      const response = await api.login(username, password);
      
      const keys = await KeyStorage.loadKeys(response.user.id);
      
      if (!keys) {
        setError('Private keys not found. Please register again.');
        addLog('error', 'Private keys not found in secure storage');
        return;
      }
      
      addLog('success', `User ${username} logged in successfully`);
      addLog('info', 'Private keys loaded from IndexedDB');
      
      // Set user and view - useEffect will handle loading users
      setUser(response.user);
      setView('chat');
      // DON'T call loadUsers() here - let useEffect handle it
      
    } catch (err) {
      setError(err.message);
      addLog('error', `Login failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    addLog('info', 'User logged out');
    
    // Clear all state INCLUDING conversation cache
    setUser(null);
    setSelectedUser(null);
    setMessages([]);
    setFiles([]);
    setUsers([]);
    setSessionKeys({});
    setSecurityLogs([]);
    setConversationCache({}); // Clear conversation cache on logout
    messageSequence.current = {};
    setView('login');
    setAuthForm({ username: '', password: '' });
  };

  // ===========================================================================
  // KEY EXCHANGE PROTOCOL - FIXED FOR BIDIRECTIONAL COMMUNICATION
  // ===========================================================================

  const initiateKeyExchange = async (recipient) => {
    try {
      addLog('info', `Initiating key exchange with ${recipient.username}...`);
      console.log('🔑 Starting key exchange with:', recipient.username);
      
      // Load sender's private keys
      const senderKeys = await KeyStorage.loadKeys(user.id);
      
      // Use the sender's STATIC ECDH private key (not ephemeral)
      // This way, both users can derive the same shared secret using their static keys
      
      console.log('📡 Getting recipient public key...');
      
      // Import recipient's ECDH public key
      const recipientECDHPublic = await CryptoUtils.importECDHPublicKey(
        recipient.ecdhPublicKey
      );
      
      console.log('🔐 Deriving shared secret...');
      
      // Derive shared secret using sender's private key and recipient's public key
      const sharedSecret = await CryptoUtils.deriveSharedSecret(
        senderKeys.ecdhPrivate,
        recipientECDHPublic
      );
      
      console.log('🧂 Generating salt and deriving session key...');
      
      // Generate salt deterministically based on both user IDs
      // This ensures both users derive the SAME session key
      const userIds = [user.id, recipient._id].sort(); // Sort to ensure same order
      const saltString = userIds.join('-');
      const saltBytes = new TextEncoder().encode(saltString);
      
      // Derive session key using HKDF
      const sessionKey = await CryptoUtils.deriveAESKey(sharedSecret, saltBytes);
      
      console.log('✅ Session key derived successfully');
      
      // Store session key
      setSessionKeys(prev => ({
        ...prev,
        [recipient._id]: {
          key: sessionKey,
          timestamp: Date.now(),
          established: Date.now()
        }
      }));
      
      // Initialize message sequence counter
      messageSequence.current[recipient._id] = 0;
      
      addLog('success', `Session key established with ${recipient.username}`);
      addLog('info', 'Secure channel ready for communication');
      
      console.log('💾 Session key stored for:', recipient.username);
      
      setSelectedUser(recipient);
      
    } catch (err) {
      console.error('❌ Key exchange failed:', err);
      addLog('error', `Key exchange failed: ${err.message}`);
    }
  };

  // ===========================================================================
  // MESSAGE HANDLING
  // ===========================================================================

  const sendMessage = async () => {
    if (!messageInput.trim() || !selectedUser) return;
    
    try {
      const session = sessionKeys[selectedUser._id];
      
      if (!session) {
        addLog('warning', 'No session key available. Initiating key exchange...');
        await initiateKeyExchange(selectedUser);
        return;
      }

      const sequence = ++messageSequence.current[selectedUser._id];
      
      const messageData = {
        content: messageInput,
        sequence,
        timestamp: Date.now(),
        nonce: CryptoUtils.generateNonce()
      };
      
      addLog('info', `Encrypting message (seq: ${sequence})...`);
      
      const encrypted = await CryptoUtils.encryptAESGCM(
        session.key,
        JSON.stringify(messageData)
      );
      
      const senderKeys = await KeyStorage.loadKeys(user.id);
      const signData = new TextEncoder().encode(
        JSON.stringify({ 
          ciphertext: encrypted.ciphertext, 
          iv: encrypted.iv, 
          sequence 
        })
      );
      const signature = await CryptoUtils.sign(senderKeys.ecdsaPrivate, signData);
      
      await api.sendMessage({
        senderId: user.id,
        recipientId: selectedUser._id,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        signature,
        sequence,
        nonce: messageData.nonce
      });
      
      addLog('success', `Message sent (seq: ${sequence})`);
      
      // Add to local messages
      const newMessage = {
        senderId: user.id,
        content: messageInput,
        timestamp: Date.now(),
        sequence
      };
      
      setMessages(prev => [...prev, newMessage]);
      
      // Update cache
      const cacheKey = selectedUser._id;
      setConversationCache(prev => ({
        ...prev,
        [cacheKey]: {
          ...prev[cacheKey],
          messages: [...(prev[cacheKey]?.messages || []), newMessage]
        }
      }));
      
      setMessageInput('');
      
    } catch (err) {
      addLog('error', `Failed to send message: ${err.message}`);
    }
  };

  const loadMessages = async () => {
    if (!selectedUser || !sessionKeys[selectedUser._id]) {
      console.log('⚠️ Cannot load messages - selectedUser:', selectedUser?.username, 'sessionKey exists:', !!sessionKeys[selectedUser?._id]);
      return;
    }
    
    try {
      // Check if we have cached messages for this conversation
      const cacheKey = selectedUser._id;
      if (conversationCache[cacheKey]?.messages && conversationCache[cacheKey].messages.length > 0) {
        console.log('📦 Loading messages from cache:', conversationCache[cacheKey].messages.length);
        setMessages(conversationCache[cacheKey].messages);
        addLog('info', `Loaded ${conversationCache[cacheKey].messages.length} messages from cache`);
        return;
      }
      
      console.log('🔄 Fetching messages from server...');
      addLog('info', `Loading messages with ${selectedUser.username}...`);
      
      const encryptedMessages = await api.getMessages(user.id, selectedUser._id);
      console.log('📨 Received encrypted messages:', encryptedMessages.length);
      
      const session = sessionKeys[selectedUser._id];
      const decryptedMessages = [];
      
      for (const msg of encryptedMessages) {
        try {
          console.log('🔓 Decrypting message from:', msg.senderId);
          
          const decrypted = await CryptoUtils.decryptAESGCM(
            session.key,
            msg.ciphertext,
            msg.iv
          );
          
          const messageData = JSON.parse(decrypted);
          console.log('✅ Decrypted message:', messageData);
          
          const senderId = msg.senderId;
          const expectedSeq = messageSequence.current[senderId] || 0;
          
          if (messageData.sequence <= expectedSeq && senderId !== user.id) {
            addLog('error', `Replay attack detected! Message seq ${messageData.sequence} <= ${expectedSeq}`);
            continue;
          }
          
          if (!CryptoUtils.validateTimestamp(messageData.timestamp)) {
            addLog('warning', `Message timestamp too old: ${new Date(messageData.timestamp).toISOString()}`);
          }
          
          if (senderId !== user.id) {
            messageSequence.current[senderId] = messageData.sequence;
          }
          
          decryptedMessages.push({
            senderId,
            content: messageData.content,
            timestamp: messageData.timestamp,
            sequence: messageData.sequence
          });
          
        } catch (err) {
          console.error('❌ Failed to decrypt message:', err);
          addLog('error', `Failed to decrypt message: ${err.message}`);
        }
      }
      
      console.log('✅ Total decrypted messages:', decryptedMessages.length);
      setMessages(decryptedMessages);
      
      // Cache the decrypted messages
      setConversationCache(prev => ({
        ...prev,
        [cacheKey]: {
          ...prev[cacheKey],
          messages: decryptedMessages
        }
      }));
      
      addLog('info', `Loaded ${decryptedMessages.length} messages`);
      
    } catch (err) {
      console.error('❌ Load messages error:', err);
      addLog('error', `Failed to load messages: ${err.message}`);
    }
  };

  // ===========================================================================
  // FILE HANDLING
  // ===========================================================================

  const handleFileSelect = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    try {
      if (!selectedUser || !sessionKeys[selectedUser._id]) {
        addLog('error', 'No session established for file transfer');
        alert('Please wait for secure connection to be established');
        return;
      }

      addLog('info', `Encrypting file: ${file.name} (${(file.size / 1024).toFixed(2)} KB)...`);
      console.log('📎 Encrypting file:', file.name, 'Size:', file.size, 'bytes');
      
      const reader = new FileReader();
      
      reader.onload = async (e) => {
        try {
          const fileData = new Uint8Array(e.target.result);
          const session = sessionKeys[selectedUser._id];
          
          console.log('🔐 Encrypting file with session key...');
          
          // Encrypt file with AES-256-GCM using the SAME session key as messages
          const encrypted = await CryptoUtils.encryptFileAESGCM(
            session.key,
            fileData.buffer
          );
          
          console.log('✍️ Signing encrypted file...');
          
          // Sign encrypted file
          const senderKeys = await KeyStorage.loadKeys(user.id);
          const signData = new TextEncoder().encode(
            JSON.stringify({ 
              filename: file.name,
              ciphertext: Array.from(encrypted.ciphertext).slice(0, 100), // Just sign first 100 bytes for signature
              iv: encrypted.iv 
            })
          );
          const signature = await CryptoUtils.sign(senderKeys.ecdsaPrivate, signData);
          
          console.log('📤 Uploading encrypted file to server...');
          
          // Upload encrypted file
          await api.uploadFile({
            senderId: user.id,
            recipientId: selectedUser._id,
            filename: file.name,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            signature
          });
          
          console.log('✅ File uploaded successfully');
          addLog('success', `File encrypted and uploaded: ${file.name}`);
          
          // Force reload files from server (bypass cache)
          await loadFiles(true);
          
        } catch (err) {
          console.error('❌ File encryption failed:', err);
          addLog('error', `File encryption failed: ${err.message}`);
          alert(`Failed to encrypt file: ${err.message}`);
        }
      };
      
      reader.onerror = (err) => {
        console.error('❌ File read failed:', err);
        addLog('error', 'Failed to read file');
        alert('Failed to read file');
      };
      
      reader.readAsArrayBuffer(file);
      
    } catch (err) {
      console.error('❌ File handling error:', err);
      addLog('error', `File handling error: ${err.message}`);
      alert(`File handling error: ${err.message}`);
    }
    
    event.target.value = '';
  };

  const loadFiles = async (forceRefresh = false) => {
    if (!selectedUser || !sessionKeys[selectedUser._id]) return;
    
    try {
      const cacheKey = selectedUser._id;
      
      // Check cache first (unless force refresh)
      if (!forceRefresh && conversationCache[cacheKey]?.files) {
        console.log('📦 Loading files from cache');
        setFiles(conversationCache[cacheKey].files);
        return;
      }
      
      console.log('🔄 Fetching files from server...');
      
      const encryptedFiles = await api.getFiles(user.id, selectedUser._id);
      
      console.log('📎 Received files:', encryptedFiles.length);
      
      setFiles(encryptedFiles);
      
      // Cache the files
      setConversationCache(prev => ({
        ...prev,
        [cacheKey]: {
          ...prev[cacheKey],
          files: encryptedFiles
        }
      }));
      
      addLog('info', `Loaded ${encryptedFiles.length} files`);
    } catch (err) {
      console.error('❌ Failed to load files:', err);
      addLog('error', `Failed to load files: ${err.message}`);
    }
  };

  const downloadFile = async (file) => {
    try {
      if (!selectedUser || !sessionKeys[selectedUser._id]) {
        addLog('error', 'No session key available for file decryption');
        alert('Please establish a secure connection first by clicking the user');
        return;
      }
      
      console.log('📥 Starting file download:', file.filename);
      addLog('info', `Decrypting file: ${file.filename}...`);
      
      const session = sessionKeys[selectedUser._id];
      
      console.log('🔓 Decrypting file with session key...');
      console.log('File ciphertext length:', file.ciphertext.length);
      console.log('File IV length:', file.iv.length);
      
      // Decrypt file using the SAME session key as messages
      const decrypted = await CryptoUtils.decryptFileAESGCM(
        session.key,
        file.ciphertext,
        file.iv
      );
      
      console.log('✅ File decrypted successfully, size:', decrypted.byteLength, 'bytes');
      
      // Create download link
      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      console.log('💾 File downloaded:', file.filename);
      addLog('success', `File decrypted and downloaded: ${file.filename}`);
      
    } catch (err) {
      console.error('❌ File decryption failed:', err);
      console.error('Error details:', {
        name: err.name,
        message: err.message,
        stack: err.stack
      });
      addLog('error', `File decryption failed: ${err.message}`);
      alert(`Failed to decrypt file: ${err.message}\n\nMake sure both users have established a secure connection.`);
    }
  };

  // ===========================================================================
  // EFFECTS
  // ===========================================================================

  // Load messages when selected user changes or session key is established
  useEffect(() => {
    if (selectedUser && sessionKeys[selectedUser._id]) {
      // Check if we have cached data first
      const cacheKey = selectedUser._id;
      if (conversationCache[cacheKey]?.messages) {
        console.log('📦 Restoring cached messages');
        setMessages(conversationCache[cacheKey].messages);
      } else {
        loadMessages();
      }
      
      // Always load files fresh (don't rely on cache for initial load)
      loadFiles(true);
    } else if (selectedUser && !sessionKeys[selectedUser._id]) {
      // Clear messages when switching to a user without a session key
      setMessages([]);
      setFiles([]);
    }
  }, [selectedUser, sessionKeys]);
  
  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    const messagesContainer = document.querySelector('.messages-container');
    if (messagesContainer) {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
  }, [messages]);

  // ===========================================================================
  // RENDER FUNCTIONS
  // ===========================================================================

  const renderLogin = () => (
    <div className="auth-container">
      <div className="auth-card">
        <h1>🔐 E2EE Secure Chat</h1>
        <p className="subtitle">End-to-End Encrypted Communication</p>
        
        {error && (
          <div className="error-message">
            ⚠️ {error}
          </div>
        )}
        
        <div className="form-group">
          <input
            type="text"
            placeholder="Username"
            value={authForm.username}
            onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
            disabled={loading}
          />
        </div>
        
        <div className="form-group">
          <input
            type="password"
            placeholder="Password"
            value={authForm.password}
            onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
            onKeyPress={(e) => e.key === 'Enter' && (view === 'login' ? handleLogin() : handleRegister())}
            disabled={loading}
          />
        </div>
        
        <div className="button-group">
          {view === 'login' ? (
            <>
              <button onClick={handleLogin} disabled={loading} className="btn-primary">
                {loading ? 'Logging in...' : 'Login'}
              </button>
              <button onClick={() => setView('register')} disabled={loading} className="btn-secondary">
                Register
              </button>
            </>
          ) : (
            <>
              <button onClick={handleRegister} disabled={loading} className="btn-primary">
                {loading ? 'Registering...' : 'Register'}
              </button>
              <button onClick={() => setView('login')} disabled={loading} className="btn-secondary">
                Back to Login
              </button>
            </>
          )}
        </div>
        
        <div className="security-info">
          <p>🔒 AES-256-GCM Encryption</p>
          <p>🔑 ECDH P-384 Key Exchange</p>
          <p>✍️ ECDSA P-384 Signatures</p>
        </div>
      </div>
    </div>
  );

  const renderChat = () => (
    <div className="chat-container">
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>👤 {user?.username || 'User'}</h2>
          <div className="header-buttons">
            <button onClick={() => setView('logs')} className="btn-icon" title="Security Logs">
              📊
            </button>
            <button onClick={handleLogout} className="btn-icon" title="Logout">
              🚪
            </button>
          </div>
        </div>
        
        <div className="user-list">
          <h3>Users ({users.length})</h3>
          {users.length === 0 ? (
            <div style={{ padding: '20px', textAlign: 'center', color: '#888' }}>
              No other users yet.<br/>
              Register another account!
            </div>
          ) : (
            users.map((u) => (
              <div
                key={u._id}
                className={`user-item ${selectedUser?._id === u._id ? 'active' : ''}`}
                onClick={() => {
                  setSelectedUser(u);
                  if (!sessionKeys[u._id]) {
                    initiateKeyExchange(u);
                  }
                }}
              >
                <div className="user-avatar">{u.username[0].toUpperCase()}</div>
                <div className="user-info">
                  <div className="user-name">{u.username}</div>
                  <div className="user-status">
                    {sessionKeys[u._id] ? '🔒 Secure' : '🔓 Not connected'}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
      
      <div className="chat-main">
        {selectedUser ? (
          <>
            <div className="chat-header">
              <h2>💬 Chat with {selectedUser.username}</h2>
              {sessionKeys[selectedUser._id] && (
                <span className="secure-badge">🔒 End-to-End Encrypted</span>
              )}
            </div>
            
            <div className="messages-container">
              {messages.length === 0 ? (
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  height: '100%',
                  color: '#888',
                  flexDirection: 'column',
                  gap: '10px'
                }}>
                  <div>💬 No messages yet</div>
                  <div style={{ fontSize: '14px' }}>Send a message to start the conversation</div>
                </div>
              ) : (
                messages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`message ${msg.senderId === user.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-content">{msg.content}</div>
                    <div className="message-meta">
                      {msg.senderId === user.id ? 'You' : selectedUser.username} • Seq: {msg.sequence} • {new Date(msg.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
            </div>
            
            <div className="files-section">
              <h4>📎 Files ({files.length})</h4>
              <div className="files-list">
                {files.length === 0 ? (
                  <div style={{ padding: '10px', textAlign: 'center', color: '#888', fontSize: '14px' }}>
                    No files shared yet
                  </div>
                ) : (
                  files.map((file) => (
                    <div key={file._id} className="file-item">
                      <span>📄 {file.filename}</span>
                      <button onClick={() => downloadFile(file)} className="btn-download">
                        Download
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
            
            <div className="input-area">
              <input
                type="text"
                placeholder="Type a message..."
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
              />
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                style={{ display: 'none' }}
              />
              <button onClick={() => fileInputRef.current.click()} className="btn-icon">
                📎
              </button>
              <button onClick={sendMessage} className="btn-send">
                Send
              </button>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <h2>👈 Select a user to start chatting</h2>
            <p>All messages are end-to-end encrypted</p>
          </div>
        )}
      </div>
    </div>
  );

  const renderLogs = () => (
    <div className="logs-container">
      <div className="logs-header">
        <h2>📊 Security Logs</h2>
        <button onClick={() => setView('chat')} className="btn-secondary">
          Back to Chat
        </button>
      </div>
      
      <div className="logs-list">
        {securityLogs.map((log, idx) => (
          <div key={idx} className={`log-item log-${log.type}`}>
            <span className="log-time">
              {new Date(log.timestamp).toLocaleString()}
            </span>
            <span className="log-type">[{log.type.toUpperCase()}]</span>
            <span className="log-message">{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );

  // ===========================================================================
  // MAIN RENDER
  // ===========================================================================

  return (
    <div className="app">
      {view === 'login' || view === 'register' ? renderLogin() : 
       view === 'logs' ? renderLogs() : renderChat()}
    </div>
  );
}

export default App;