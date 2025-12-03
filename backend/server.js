const dotenv=require('dotenv');
dotenv.config();
const express = require('express');
const { connectDB } = require('./config/database');
const requestLogger = require('./middleware/logger');
const corsMiddleware = require('./middleware/cors');

// Import Routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const keyExchangeRoutes = require('./routes/keyExchangeRoutes');
const messageRoutes = require('./routes/messageRoutes');
const fileRoutes = require('./routes/fileRoutes');
const securityRoutes = require('./routes/securityRoutes');

const app = express();

// Request logging
app.use(requestLogger);

// CORS configuration
app.use(corsMiddleware);

// Body parser
app.use(express.json({ limit: '50mb' }));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/key-exchange', keyExchangeRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/security', securityRoutes);

app.get('/api/logs/:userId', (req, res, next) => {
  req.url = `/api/security/logs/${req.params.userId}`;
  app._router.handle(req, res, next);
});

app.get('/api/logs', (req, res, next) => {
  req.url = '/api/security/logs';
  app._router.handle(req, res, next);
});

app.get('/api/security/replay-stats', (req, res, next) => {
  req.url = '/api/security/replay-stats';
  app._router.handle(req, res, next);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 3001;

const startServer = async () => {
  try {
    // Connect to database
    await connectDB();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log('E2EE Secure Communication System Backend Active');
      console.log('CORS enabled for http://localhost:3000');
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
};

startServer();

module.exports = app;