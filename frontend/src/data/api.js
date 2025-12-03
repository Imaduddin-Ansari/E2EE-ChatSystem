const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

const api = {

  async register(userData) {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }

      return data;
    } catch (err) {
      console.error('Register API error:', err);
      throw err;
    }
  },

  async login(username, password) {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      return data;
    } catch (err) {
      console.error('Login API error:', err);
      throw err;
    }
  },

  async getUsers(userId) {
    try {
      const response = await fetch(`${API_BASE_URL}/users/${userId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch users');
      }

      return data.users;
    } catch (err) {
      console.error('Get users API error:', err);
      throw err;
    }
  },

  async getUserProfile(userId) {
    try {
      const response = await fetch(`${API_BASE_URL}/users/profile/${userId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch user profile');
      }

      return data.user;
    } catch (err) {
      console.error('Get user profile API error:', err);
      throw err;
    }
  },
  async initiateKeyExchange(keyExchangeData) {
    try {
      const response = await fetch(`${API_BASE_URL}/key-exchange/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(keyExchangeData)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Key exchange failed');
      }

      return data.recipientPublicKeys;
    } catch (err) {
      console.error('Key exchange API error:', err);
      throw err;
    }
  },

  async sendMessage(messageData) {
    try {
      const response = await fetch(`${API_BASE_URL}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(messageData)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to send message');
      }

      return data;
    } catch (err) {
      console.error('Send message API error:', err);
      throw err;
    }
  },

  async getMessages(userId, recipientId) {
    try {
      const response = await fetch(`${API_BASE_URL}/messages/${userId}/${recipientId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch messages');
      }

      return data.messages;
    } catch (err) {
      console.error('Get messages API error:', err);
      throw err;
    }
  },

  async uploadFile(fileData) {
    try {
      const response = await fetch(`${API_BASE_URL}/files`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(fileData)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to upload file');
      }

      return data;
    } catch (err) {
      console.error('Upload file API error:', err);
      throw err;
    }
  },

  async getFiles(userId, recipientId) {
    try {
      const response = await fetch(`${API_BASE_URL}/files/${userId}/${recipientId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch files');
      }

      return data.files;
    } catch (err) {
      console.error('Get files API error:', err);
      throw err;
    }
  },

  async getUserLogs(userId) {
    try {
      const response = await fetch(`${API_BASE_URL}/logs/${userId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch logs');
      }

      return data.logs;
    } catch (err) {
      console.error('Get logs API error:', err);
      throw err;
    }
  },

  async getAllLogs() {
    try {
      const response = await fetch(`${API_BASE_URL}/logs`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch logs');
      }

      return data.logs;
    } catch (err) {
      console.error('Get all logs API error:', err);
      throw err;
    }
  },

  async getSecurityStats() {
    try {
      const response = await fetch(`${API_BASE_URL}/security/replay-stats`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch stats');
      }

      return data.stats;
    } catch (err) {
      console.error('Get security stats API error:', err);
      throw err;
    }
  }
};

export default api;