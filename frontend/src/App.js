import React, { useState, useEffect, useRef } from 'react';
import CryptoUtils from './data/cryptoUtils';
import KeyStorage from './data/keyStorage';
import api from './data/api';
import './App.css';

const ShieldIcon = () => (
  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

const LockIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);

const UnlockIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
  </svg>
);

const KeyIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
  </svg>
);

const SendIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="22" y1="2" x2="11" y2="13"/>
    <polygon points="22 2 15 22 11 13 2 9 22 2"/>
  </svg>
);

const PaperclipIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
  </svg>
);

const LogOutIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
    <polyline points="16 17 21 12 16 7"/>
    <line x1="21" y1="12" x2="9" y2="12"/>
  </svg>
);

const ChartIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10"/>
    <line x1="12" y1="20" x2="12" y2="4"/>
    <line x1="6" y1="20" x2="6" y2="14"/>
  </svg>
);

const DownloadIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
    <polyline points="7 10 12 15 17 10"/>
    <line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
);

const ArrowLeftIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="19" y1="12" x2="5" y2="12"/>
    <polyline points="12 19 5 12 12 5"/>
  </svg>
);

const MessageIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
  </svg>
);

const FileIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="16" y1="13" x2="8" y2="13"/>
    <line x1="16" y1="17" x2="8" y2="17"/>
  </svg>
);

const FingerprintIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/>
    <path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/>
    <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/>
    <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/>
    <path d="M8.65 22c.21-.66.45-1.32.57-2"/>
    <path d="M14 13.12c0 2.38 0 6.38-1 8.88"/>
    <path d="M2 16h.01"/>
    <path d="M21.8 16c.2-2 .131-5.354 0-6"/>
    <path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2"/>
  </svg>
);

const LoaderIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="animate-spin">
    <line x1="12" y1="2" x2="12" y2="6"/>
    <line x1="12" y1="18" x2="12" y2="22"/>
    <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/>
    <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
    <line x1="2" y1="12" x2="6" y2="12"/>
    <line x1="18" y1="12" x2="22" y2="12"/>
    <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/>
    <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>
  </svg>
);

const CheckCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
    <polyline points="22 4 12 14.01 9 11.01"/>
  </svg>
);

const AlertCircleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);

const AlertTriangleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);

const InfoIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="16" x2="12" y2="12"/>
    <line x1="12" y1="8" x2="12.01" y2="8"/>
  </svg>
);

function App() {
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
  const [conversationCache, setConversationCache] = useState({});

  const messageSequence = useRef({});
  const fileInputRef = useRef(null);
  const messagesEndRef = useRef(null);

  const addLog = (type, message) => {
    const log = {
      type,
      message,
      timestamp: new Date().toISOString()
    };
    setSecurityLogs(prev => [log, ...prev].slice(0, 50));
    console.log(`[${type.toUpperCase()}] ${message}`);
  };

  const loadUsers = async () => {
    try {
      if (!user || !user.id) return;
      const userList = await api.getUsers(user.id);
      setUsers(userList);
      addLog('info', `Loaded ${userList.length} users`);
    } catch (err) {
      addLog('error', `Failed to load users: ${err.message}`);
    }
  };

  useEffect(() => {
    if (user && view === 'chat') {
      loadUsers();
    }
  }, [user, view]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

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

      setUser(response.user);
      setView('chat');
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

      setUser(response.user);
      setView('chat');
    } catch (err) {
      setError(err.message);
      addLog('error', `Login failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    addLog('info', 'User logged out');
    setUser(null);
    setSelectedUser(null);
    setMessages([]);
    setFiles([]);
    setUsers([]);
    setSessionKeys({});
    setSecurityLogs([]);
    setConversationCache({});
    messageSequence.current = {};
    setView('login');
    setAuthForm({ username: '', password: '' });
  };

  const initiateKeyExchange = async (recipient) => {
    try {
      if (!user) return;

      addLog('info', `Initiating key exchange with ${recipient.username}...`);

      const senderKeys = await KeyStorage.loadKeys(user.id);
      if (!senderKeys) {
        addLog('error', 'Sender keys not found');
        return;
      }

      const recipientECDHPublic = await CryptoUtils.importECDHPublicKey(recipient.ecdhPublicKey);

      const sharedSecret = await CryptoUtils.deriveSharedSecret(
        senderKeys.ecdhPrivate,
        recipientECDHPublic
      );

      const userIds = [user.id, recipient._id].sort();
      const saltString = userIds.join('-');
      const saltBytes = new TextEncoder().encode(saltString);

      const sessionKey = await CryptoUtils.deriveAESKey(sharedSecret, saltBytes);

      setSessionKeys(prev => ({
        ...prev,
        [recipient._id]: {
          key: sessionKey,
          timestamp: Date.now(),
          established: Date.now()
        }
      }));

      messageSequence.current[recipient._id] = 0;

      addLog('success', `Session key established with ${recipient.username}`);
      addLog('info', 'Secure channel ready for communication');

      setSelectedUser(recipient);
    } catch (err) {
      addLog('error', `Key exchange failed: ${err.message}`);
    }
  };

  const sendMessage = async () => {
    if (!messageInput.trim() || !selectedUser || !user) return;

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
      if (!senderKeys) return;

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

      const newMessage = {
        senderId: user.id,
        content: messageInput,
        timestamp: Date.now(),
        sequence
      };

      setMessages(prev => [...prev, newMessage]);

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
    if (!selectedUser || !sessionKeys[selectedUser._id] || !user) return;

    try {
      const cacheKey = selectedUser._id;
      if (conversationCache[cacheKey]?.messages && conversationCache[cacheKey].messages.length > 0) {
        setMessages(conversationCache[cacheKey].messages);
        addLog('info', `Loaded ${conversationCache[cacheKey].messages.length} messages from cache`);
        return;
      }

      addLog('info', `Loading messages with ${selectedUser.username}...`);

      const encryptedMessages = await api.getMessages(user.id, selectedUser._id);
      const session = sessionKeys[selectedUser._id];
      const decryptedMessages = [];

      for (const msg of encryptedMessages) {
        try {
          const decrypted = await CryptoUtils.decryptAESGCM(
            session.key,
            msg.ciphertext,
            msg.iv
          );

          const messageData = JSON.parse(decrypted);
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
          addLog('error', `Failed to decrypt message: ${err.message}`);
        }
      }

      setMessages(decryptedMessages);

      setConversationCache(prev => ({
        ...prev,
        [cacheKey]: {
          ...prev[cacheKey],
          messages: decryptedMessages
        }
      }));

      addLog('info', `Loaded ${decryptedMessages.length} messages`);
    } catch (err) {
      addLog('error', `Failed to load messages: ${err.message}`);
    }
  };

  const handleFileSelect = async (event) => {
    const file = event.target.files?.[0];
    if (!file || !selectedUser || !user) return;

    try {
      if (!sessionKeys[selectedUser._id]) {
        addLog('error', 'No session established for file transfer');
        alert('Please wait for secure connection to be established');
        return;
      }

      addLog('info', `Encrypting file: ${file.name} (${(file.size / 1024).toFixed(2)} KB)...`);

      const reader = new FileReader();

      reader.onload = async (e) => {
        try {
          const fileData = new Uint8Array(e.target.result);
          const session = sessionKeys[selectedUser._id];

          const encrypted = await CryptoUtils.encryptFileAESGCM(session.key, fileData.buffer);

          const senderKeys = await KeyStorage.loadKeys(user.id);
          if (!senderKeys) return;

          const signData = new TextEncoder().encode(
            JSON.stringify({
              filename: file.name,
              ciphertext: Array.from(encrypted.ciphertext).slice(0, 100),
              iv: encrypted.iv
            })
          );
          const signature = await CryptoUtils.sign(senderKeys.ecdsaPrivate, signData);

          await api.uploadFile({
            senderId: user.id,
            recipientId: selectedUser._id,
            filename: file.name,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            signature
          });

          addLog('success', `File encrypted and uploaded: ${file.name}`);
          await loadFiles(true);
        } catch (err) {
          addLog('error', `File encryption failed: ${err.message}`);
          alert(`Failed to encrypt file: ${err.message}`);
        }
      };

      reader.onerror = () => {
        addLog('error', 'Failed to read file');
        alert('Failed to read file');
      };

      reader.readAsArrayBuffer(file);
    } catch (err) {
      addLog('error', `File handling error: ${err.message}`);
      alert(`File handling error: ${err.message}`);
    }

    event.target.value = '';
  };

  const loadFiles = async (forceRefresh = false) => {
    if (!selectedUser || !sessionKeys[selectedUser._id] || !user) return;

    try {
      const cacheKey = selectedUser._id;

      if (!forceRefresh && conversationCache[cacheKey]?.files) {
        setFiles(conversationCache[cacheKey].files);
        return;
      }

      const encryptedFiles = await api.getFiles(user.id, selectedUser._id);

      setFiles(encryptedFiles);

      setConversationCache(prev => ({
        ...prev,
        [cacheKey]: {
          ...prev[cacheKey],
          files: encryptedFiles
        }
      }));

      addLog('info', `Loaded ${encryptedFiles.length} files`);
    } catch (err) {
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

      addLog('info', `Decrypting file: ${file.filename}...`);

      const session = sessionKeys[selectedUser._id];

      const decrypted = await CryptoUtils.decryptFileAESGCM(
        session.key,
        file.ciphertext,
        file.iv
      );

      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      addLog('success', `File decrypted and downloaded: ${file.filename}`);
    } catch (err) {
      addLog('error', `File decryption failed: ${err.message}`);
      alert(`Failed to decrypt file: ${err.message}\n\nMake sure both users have established a secure connection.`);
    }
  };

  useEffect(() => {
    if (selectedUser && sessionKeys[selectedUser._id]) {
      const cacheKey = selectedUser._id;
      if (conversationCache[cacheKey]?.messages) {
        setMessages(conversationCache[cacheKey].messages);
      } else {
        loadMessages();
      }
      loadFiles(true);
    } else if (selectedUser && !sessionKeys[selectedUser._id]) {
      setMessages([]);
      setFiles([]);
    }
  }, [selectedUser, sessionKeys]);

  const handleUserClick = (u) => {
    setSelectedUser(u);
    if (!sessionKeys[u._id]) {
      initiateKeyExchange(u);
    }
  };

  const getLogIcon = (type) => {
    switch (type) {
      case 'success': return <CheckCircleIcon />;
      case 'error': return <AlertCircleIcon />;
      case 'warning': return <AlertTriangleIcon />;
      default: return <InfoIcon />;
    }
  };

  // Auth View
  const renderAuth = () => (
    <div className="auth-container">
      <div className="ambient-glow glow-1" />
      <div className="ambient-glow glow-2" />

      <div className="auth-wrapper">
        <div className="auth-header">
          <div className="shield-icon">
            <ShieldIcon />
          </div>
          <h1 className="auth-title">Secure Chat</h1>
          <p className="auth-subtitle">End-to-End Encrypted Communication</p>
        </div>

        <div className="auth-card">
          {error && (
            <div className="error-banner">
              <div className="error-icon">!</div>
              <p>{error}</p>
            </div>
          )}

          <div className="form-fields">
            <input
              type="text"
              placeholder="Username"
              value={authForm.username}
              onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
              disabled={loading}
              className="form-input"
            />
            <input
              type="password"
              placeholder="Password"
              value={authForm.password}
              onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
              onKeyPress={(e) => e.key === 'Enter' && (view === 'login' ? handleLogin() : handleRegister())}
              disabled={loading}
              className="form-input"
            />
          </div>

          <div className="button-group">
            {view === 'login' ? (
              <>
                <button onClick={handleLogin} disabled={loading} className="btn-primary">
                  {loading ? <LoaderIcon /> : <><LockIcon size={16} /> Login</>}
                </button>
                <button onClick={() => setView('register')} disabled={loading} className="btn-secondary">
                  Register
                </button>
              </>
            ) : (
              <>
                <button onClick={handleRegister} disabled={loading} className="btn-primary">
                  {loading ? <LoaderIcon /> : <><KeyIcon size={16} /> Create Account</>}
                </button>
                <button onClick={() => setView('login')} disabled={loading} className="btn-secondary">
                  Back
                </button>
              </>
            )}
          </div>
        </div>

        <div className="security-badges">
          <div className="badge">
            <LockIcon size={24} />
            <span>AES-256-GCM</span>
          </div>
          <div className="badge">
            <KeyIcon size={24} />
            <span>ECDH P-384</span>
          </div>
          <div className="badge">
            <FingerprintIcon />
            <span>ECDSA Signatures</span>
          </div>
        </div>
      </div>
    </div>
  );

  // Chat View
  const renderChat = () => (
    <div className="chat-layout">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="user-profile">
            <div className="avatar">{user?.username[0].toUpperCase()}</div>
            <div className="user-details">
              <p className="username">{user?.username}</p>
              <p className="status"><LockIcon size={12} /> Secure</p>
            </div>
          </div>
          <div className="header-actions">
            <button onClick={() => setView('logs')} className="icon-btn" title="Security Logs">
              <ChartIcon />
            </button>
            <button onClick={handleLogout} className="icon-btn logout-btn" title="Logout">
              <LogOutIcon />
            </button>
          </div>
        </div>

        <div className="user-list">
          <p className="list-header">Users ({users.length})</p>

          {users.length === 0 ? (
            <div className="empty-users">
              <MessageIcon />
              <p>No other users yet</p>
              <span>Register another account to start chatting</span>
            </div>
          ) : (
            <div className="users">
              {users.map((u) => (
                <button
                  key={u._id}
                  onClick={() => handleUserClick(u)}
                  className={`user-item ${selectedUser?._id === u._id ? 'active' : ''}`}
                >
                  <div className="user-avatar">{u.username[0].toUpperCase()}</div>
                  <div className="user-info">
                    <p className="name">{u.username}</p>
                    <p className="connection-status">
                      {sessionKeys[u._id] ? (
                        <><LockIcon size={12} /> Secure</>
                      ) : (
                        <><UnlockIcon size={12} /> Not connected</>
                      )}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-main">
        {selectedUser ? (
          <>
            <div className="chat-header">
              <div className="chat-user">
                <div className="avatar">{selectedUser.username[0].toUpperCase()}</div>
                <div>
                  <h2>{selectedUser.username}</h2>
                  {sessionKeys[selectedUser._id] && (
                    <p className="encrypted-status"><LockIcon size={12} /> End-to-End Encrypted</p>
                  )}
                </div>
              </div>
              {sessionKeys[selectedUser._id] && (
                <div className="secure-badge">
                  <LockIcon size={14} />
                  Secure Channel
                </div>
              )}
            </div>

            <div className="messages-area">
              {messages.length === 0 ? (
                <div className="empty-messages">
                  <MessageIcon />
                  <p>No messages yet</p>
                  <span>Send a message to start the conversation</span>
                </div>
              ) : (
                messages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`message ${msg.senderId === user.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-bubble">
                      <p>{msg.content}</p>
                      <span className="meta">
                        {msg.senderId === user.id ? 'You' : selectedUser.username} • Seq: {msg.sequence} • {new Date(msg.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className="files-section">
              <div className="files-header">
                <FileIcon />
                <span>Shared Files ({files.length})</span>
              </div>
              {files.length === 0 ? (
                <p className="no-files">No files shared yet</p>
              ) : (
                <div className="files-list">
                  {files.map((file) => (
                    <div key={file._id} className="file-item">
                      <FileIcon />
                      <span>{file.filename}</span>
                      <button onClick={() => downloadFile(file)} className="download-btn">
                        <DownloadIcon />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="input-area">
              <input
                type="text"
                placeholder="Type a message..."
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                className="message-input"
              />
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                style={{ display: 'none' }}
              />
              <button onClick={() => fileInputRef.current?.click()} className="attach-btn">
                <PaperclipIcon />
              </button>
              <button onClick={sendMessage} className="send-btn">
                <SendIcon />
              </button>
            </div>
          </>
        ) : (
          <div className="no-chat-selected">
            <MessageIcon />
            <h2>Select a conversation</h2>
            <p>Choose a user to start chatting</p>
            <span>All messages are end-to-end encrypted</span>
          </div>
        )}
      </div>
    </div>
  );

  // Logs View
  const renderLogs = () => (
    <div className="logs-container">
      <div className="logs-header">
        <button onClick={() => setView('chat')} className="back-btn">
          <ArrowLeftIcon />
        </button>
        <div>
          <h1>Security Logs</h1>
          <p>Cryptographic operations and events</p>
        </div>
      </div>

      <div className="logs-list">
        {securityLogs.length === 0 ? (
          <div className="empty-logs">
            <InfoIcon />
            <p>No logs yet</p>
            <span>Security events will appear here</span>
          </div>
        ) : (
          securityLogs.map((log, idx) => (
            <div key={idx} className={`log-item log-${log.type}`}>
              <div className="log-icon">{getLogIcon(log.type)}</div>
              <div className="log-content">
                <div className="log-meta">
                  <span className="log-time">{new Date(log.timestamp).toLocaleString()}</span>
                  <span className={`log-type type-${log.type}`}>{log.type.toUpperCase()}</span>
                </div>
                <p className="log-message">{log.message}</p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );

  return (
    <div className="app">
      {view === 'login' || view === 'register' ? renderAuth() :
        view === 'logs' ? renderLogs() : renderChat()}
    </div>
  );
}

export default App;
