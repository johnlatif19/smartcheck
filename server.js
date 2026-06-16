require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const admin = require('firebase-admin');

// Initialize Firebase Admin
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig)
});
const db = admin.firestore();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://*.firebaseio.com", "https://*.googleapis.com"]
    }
  }
}));

// CORS
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://smartcheck.vercel.app']
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Body parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
}));

// Static files
app.use(express.static('public'));

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    });
  }
  next();
};

app.use(sanitizeInput);

// ==================== API Routes ====================

// Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

// Generate Pairing Code
app.post('/api/generate-pairing', async (req, res) => {
  try {
    const { deviceId } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'Device ID required' });
    }

    const pairingCode = Math.floor(100000 + Math.random() * 900000).toString();
    const qrCode = await QRCode.toDataURL(pairingCode);

    // Store in Firestore
    await db.collection('devices').doc(deviceId).set({
      deviceId,
      pairingCode,
      qrCode,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    res.json({ pairingCode, qrCode });
  } catch (error) {
    console.error('Error generating pairing:', error);
    res.status(500).json({ error: 'Failed to generate pairing code' });
  }
});

// Pair Device
app.post('/api/pair-device', 
  body('pairingCode').isString().isLength({ min: 6, max: 6 }),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { pairingCode } = req.body;

      // Find device with this pairing code
      const devicesSnapshot = await db.collection('devices')
        .where('pairingCode', '==', pairingCode)
        .where('status', '==', 'pending')
        .limit(1)
        .get();

      if (devicesSnapshot.empty) {
        return res.status(404).json({ error: 'Invalid or expired pairing code' });
      }

      const deviceDoc = devicesSnapshot.docs[0];
      const deviceData = deviceDoc.data();

      // Update device status
      await deviceDoc.ref.update({
        status: 'paired',
        pairedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Generate JWT
      const token = jwt.sign(
        { deviceId: deviceData.deviceId },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        token,
        deviceId: deviceData.deviceId,
        message: 'Device paired successfully'
      });
    } catch (error) {
      console.error('Error pairing device:', error);
      res.status(500).json({ error: 'Failed to pair device' });
    }
  }
);

// Submit Device Report
app.post('/api/submit-report',
  authenticateJWT,
  body('deviceInfo').isObject(),
  body('batteryInfo').isObject(),
  body('testResults').isObject(),
  body('overallScore').isNumeric(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { deviceInfo, batteryInfo, testResults, overallScore } = req.body;
      const deviceId = req.user.deviceId;

      const reportData = {
        deviceId,
        deviceInfo,
        batteryInfo,
        testResults,
        overallScore,
        status: 'completed',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      // Save report
      const reportRef = await db.collection('reports').add(reportData);

      // Update device with latest report
      await db.collection('devices').doc(deviceId).update({
        lastReportId: reportRef.id,
        status: 'completed',
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      res.json({
        reportId: reportRef.id,
        message: 'Report submitted successfully'
      });
    } catch (error) {
      console.error('Error submitting report:', error);
      res.status(500).json({ error: 'Failed to submit report' });
    }
  }
);

// Get Device Dashboard
app.get('/api/device/:deviceId',
  authenticateJWT,
  async (req, res) => {
    try {
      const { deviceId } = req.params;

      if (req.user.deviceId !== deviceId) {
        return res.status(403).json({ error: 'Access denied' });
      }

      // Get device info
      const deviceDoc = await db.collection('devices').doc(deviceId).get();
      if (!deviceDoc.exists) {
        return res.status(404).json({ error: 'Device not found' });
      }

      const deviceData = deviceDoc.data();

      // Get latest report
      let reportData = null;
      if (deviceData.lastReportId) {
        const reportDoc = await db.collection('reports').doc(deviceData.lastReportId).get();
        if (reportDoc.exists) {
          reportData = reportDoc.data();
        }
      }

      res.json({
        device: deviceData,
        report: reportData
      });
    } catch (error) {
      console.error('Error fetching device:', error);
      res.status(500).json({ error: 'Failed to fetch device data' });
    }
  }
);

// Get All Devices (Admin)
app.get('/api/devices',
  authenticateJWT,
  async (req, res) => {
    try {
      const devicesSnapshot = await db.collection('devices')
        .orderBy('createdAt', 'desc')
        .limit(50)
        .get();

      const devices = [];
      devicesSnapshot.forEach(doc => {
        devices.push({
          id: doc.id,
          ...doc.data()
        });
      });

      res.json(devices);
    } catch (error) {
      console.error('Error fetching devices:', error);
      res.status(500).json({ error: 'Failed to fetch devices' });
    }
  }
);

// Get Reports
app.get('/api/reports',
  authenticateJWT,
  async (req, res) => {
    try {
      const { deviceId } = req.query;
      
      let query = db.collection('reports')
        .orderBy('createdAt', 'desc')
        .limit(50);

      if (deviceId) {
        query = query.where('deviceId', '==', deviceId);
      }

      const reportsSnapshot = await query.get();
      const reports = [];
      reportsSnapshot.forEach(doc => {
        reports.push({
          id: doc.id,
          ...doc.data()
        });
      });

      res.json(reports);
    } catch (error) {
      console.error('Error fetching reports:', error);
      res.status(500).json({ error: 'Failed to fetch reports' });
    }
  }
);

// Get Report by ID
app.get('/api/report/:reportId',
  authenticateJWT,
  async (req, res) => {
    try {
      const { reportId } = req.params;
      
      const reportDoc = await db.collection('reports').doc(reportId).get();
      
      if (!reportDoc.exists) {
        return res.status(404).json({ error: 'Report not found' });
      }

      const reportData = reportDoc.data();
      
      // Check if user has access
      if (req.user.deviceId !== reportData.deviceId && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }

      res.json({
        id: reportDoc.id,
        ...reportData
      });
    } catch (error) {
      console.error('Error fetching report:', error);
      res.status(500).json({ error: 'Failed to fetch report' });
    }
  }
);

// ==================== Serve React App ====================
app.get('*', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(PORT, () => {
  console.log(`🚀 SmartCheck Server running on port ${PORT}`);
});
