const File = require('../models/File');
const { logSecurityEvent } = require('../utils/securityLogger');

const uploadFile = async (req, res) => {
  try {
    const { senderId, recipientId, filename, ciphertext, iv, signature } = req.body;

    if (!senderId || !recipientId || !filename || !ciphertext || !iv || !signature) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const file = await File.create({
      senderId,
      recipientId,
      filename,
      ciphertext,
      iv,
      signature
    });

    await logSecurityEvent('FILE_UPLOAD', senderId, 
      `File uploaded: ${filename} to user ${recipientId}`, req);

    res.status(201).json({ success: true, fileId: file._id });

  } catch (err) {
    console.error('File upload error:', err);
    await logSecurityEvent('FILE_UPLOAD', req.body.senderId, 
      `File upload failed: ${err.message}`, req);
    res.status(500).json({ error: 'Failed to upload file' });
  }
};

const getFiles = async (req, res) => {
  try {
    const { userId, recipientId } = req.params;
    
    const files = await File.find({
      $or: [
        { senderId: userId, recipientId },
        { senderId: recipientId, recipientId: userId }
      ]
    }).sort({ timestamp: -1 });

    await logSecurityEvent('FILE_DOWNLOAD', userId, 
      `Retrieved ${files.length} files`, req);

    res.json({ success: true, files });

  } catch (err) {
    console.error('Get files error:', err);
    res.status(500).json({ error: 'Failed to retrieve files' });
  }
};

module.exports = { uploadFile, getFiles };