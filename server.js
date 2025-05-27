const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/custom-web';

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public/images');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed!'));
  }
});

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const linkSchema = new mongoose.Schema({
  text: { type: String, required: true },
  url: { type: String, required: true },
  icon: { type: String, default: "link" }
});

const serviceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  icon: { type: String, default: "star" }
});

const contactInfoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  value: { type: String, required: true },
  type: { type: String, enum: ['text', 'email', 'phone', 'link'], default: 'text' },
  icon: { type: String, default: "envelope" }
});

const faqSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true }
});

const profileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  profileImage: { type: String, required: true },
  logoImage: { type: String, default: "/images/logo.png" },
  backgroundColor: { type: String, default: "#ffffff" },
  textColor: { type: String, default: "#333333" },
  accentColor: { type: String, default: "#4f46e5" },
  galleryBgColor: { type: String, default: "#f9fafb" },
  servicesBgColor: { type: String, default: "#ffffff" },
  servicesSectionTitle: { type: String, default: "My Services" },
  gallerySectionTitle: { type: String, default: "My Gallery" },
  infoSectionTitle: { type: String, default: "Contact Information" },
  faqSectionTitle: { type: String, default: "Frequently Asked Questions" },
  contactSectionTitle: { type: String, default: "Contact Me" },
  showContactForm: { type: Boolean, default: true },
  contactEmail: { type: String, default: "" },
  links: [linkSchema],
  services: [serviceSchema],
  contactInfo: [contactInfoSchema],
  faqs: [faqSchema],
  galleryImages: [{ type: String }]
});

// Models
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Routes
// Serve the main page
app.get('/custom-web', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Serve the login page
app.get('/custom-web/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/login.html'));
});

// Serve the admin page
app.get('/custom-web/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

// API Routes
// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Register (for initial setup)
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Check if this is the first user
    const userCount = await User.countDocuments();
    
    if (userCount > 0) {
      return res.status(403).json({ error: 'Registration is closed' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const user = new User({
      username,
      password: hashedPassword
    });
    
    await user.save();
    
    // Create default profile
    const profile = new Profile({
      name: 'Your Name',
      description: 'Welcome to my personal profile!',
      profileImage: '/images/profile.jpg',
      logoImage: '/images/logo.png'
    });
    
    await profile.save();
    
    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get profile data
app.get('/api/profile', async (req, res) => {
  try {
    let profile = await Profile.findOne();
    
    if (!profile) {
      profile = new Profile({
        name: 'Your Name',
        description: 'Welcome to my personal profile!',
        profileImage: '/images/profile.jpg',
        logoImage: '/images/logo.png'
      });
      
      await profile.save();
    }
    
    res.json(profile);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
app.put('/api/profile', auth, async (req, res) => {
  try {
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Handle file upload separately
    if (req.files && req.files.profileImage) {
      const profileImage = req.files.profileImage[0];
      profile.profileImage = `/images/${profileImage.filename}`;
    }
    
    // Update fields
    const updateFields = [
      'name', 'description', 'backgroundColor', 'textColor', 'accentColor',
      'galleryBgColor', 'servicesBgColor', 'showContactForm', 'contactEmail',
      'servicesSectionTitle', 'gallerySectionTitle', 'infoSectionTitle',
      'faqSectionTitle', 'contactSectionTitle'
    ];
    
    updateFields.forEach(field => {
      if (req.body[field] !== undefined) {
        profile[field] = req.body[field];
      }
    });
    
    await profile.save();
    
    res.json({ message: 'Profile updated successfully', profile });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile with file upload
app.put('/api/profile', auth, upload.fields([
  { name: 'profileImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Handle file upload
    if (req.files && req.files.profileImage) {
      const profileImage = req.files.profileImage[0];
      profile.profileImage = `/images/${profileImage.filename}`;
    }
    
    // Update fields
    const updateFields = [
      'name', 'description', 'backgroundColor', 'textColor', 'accentColor',
      'galleryBgColor', 'servicesBgColor', 'showContactForm', 'contactEmail',
      'servicesSectionTitle', 'gallerySectionTitle', 'infoSectionTitle',
      'faqSectionTitle', 'contactSectionTitle'
    ];
    
    updateFields.forEach(field => {
      if (req.body[field] !== undefined) {
        profile[field] = req.body[field];
      }
    });
    
    await profile.save();
    
    res.json({ message: 'Profile updated successfully', profile });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update logo
app.put('/api/logo', auth, upload.fields([
  { name: 'logoImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Handle file upload
    if (req.files && req.files.logoImage) {
      const logoImage = req.files.logoImage[0];
      profile.logoImage = `/images/${logoImage.filename}`;
    }
    
    await profile.save();
    
    res.json({ message: 'Logo updated successfully', profile });
  } catch (error) {
    console.error('Update logo error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add service
app.post('/api/services', auth, async (req, res) => {
  try {
    const { title, description, icon } = req.body;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    profile.services.push({
      title,
      description,
      icon: icon || 'star'
    });
    
    await profile.save();
    
    res.json({ message: 'Service added successfully', profile });
  } catch (error) {
    console.error('Add service error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete service
app.delete('/api/services/:index', auth, async (req, res) => {
  try {
    const { index } = req.params;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (index < 0 || index >= profile.services.length) {
      return res.status(400).json({ error: 'Invalid service index' });
    }
    
    profile.services.splice(index, 1);
    
    await profile.save();
    
    res.json({ message: 'Service deleted successfully', profile });
  } catch (error) {
    console.error('Delete service error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add link
app.post('/api/links', auth, async (req, res) => {
  try {
    const { text, url, icon } = req.body;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    profile.links.push({
      text,
      url,
      icon: icon || 'link'
    });
    
    await profile.save();
    
    res.json({ message: 'Link added successfully', profile });
  } catch (error) {
    console.error('Add link error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete link
app.delete('/api/links/:index', auth, async (req, res) => {
  try {
    const { index } = req.params;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (index < 0 || index >= profile.links.length) {
      return res.status(400).json({ error: 'Invalid link index' });
    }
    
    profile.links.splice(index, 1);
    
    await profile.save();
    
    res.json({ message: 'Link deleted successfully', profile });
  } catch (error) {
    console.error('Delete link error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add contact info
app.post('/api/contactInfo', auth, async (req, res) => {
  try {
    const { title, value, type, icon } = req.body;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    profile.contactInfo.push({
      title,
      value,
      type: type || 'text',
      icon: icon || 'envelope'
    });
    
    await profile.save();
    
    res.json({ message: 'Contact info added successfully', profile });
  } catch (error) {
    console.error('Add contact info error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete contact info
app.delete('/api/contactInfo/:index', auth, async (req, res) => {
  try {
    const { index } = req.params;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (index < 0 || index >= profile.contactInfo.length) {
      return res.status(400).json({ error: 'Invalid contact info index' });
    }
    
    profile.contactInfo.splice(index, 1);
    
    await profile.save();
    
    res.json({ message: 'Contact info deleted successfully', profile });
  } catch (error) {
    console.error('Delete contact info error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add FAQ
app.post('/api/faqs', auth, async (req, res) => {
  try {
    const { question, answer } = req.body;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    profile.faqs.push({
      question,
      answer
    });
    
    await profile.save();
    
    res.json({ message: 'FAQ added successfully', profile });
  } catch (error) {
    console.error('Add FAQ error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete FAQ
app.delete('/api/faqs/:index', auth, async (req, res) => {
  try {
    const { index } = req.params;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (index < 0 || index >= profile.faqs.length) {
      return res.status(400).json({ error: 'Invalid FAQ index' });
    }
    
    profile.faqs.splice(index, 1);
    
    await profile.save();
    
    res.json({ message: 'FAQ deleted successfully', profile });
  } catch (error) {
    console.error('Delete FAQ error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload gallery images
app.post('/api/gallery', auth, upload.array('images', 10), async (req, res) => {
  try {
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    // Add uploaded images to gallery
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        profile.galleryImages.push(`/images/${file.filename}`);
      });
    }
    
    await profile.save();
    
    res.json({ message: 'Gallery images uploaded successfully', profile });
  } catch (error) {
    console.error('Upload gallery images error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete gallery image
app.delete('/api/gallery/:index', auth, async (req, res) => {
  try {
    const { index } = req.params;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (index < 0 || index >= profile.galleryImages.length) {
      return res.status(400).json({ error: 'Invalid gallery image index' });
    }
    
    // Get the image path
    const imagePath = profile.galleryImages[index];
    
    // Remove from database
    profile.galleryImages.splice(index, 1);
    await profile.save();
    
    // Delete file if it's not a default image
    if (!imagePath.includes('placeholder') && !imagePath.includes('default')) {
      const fullPath = path.join(__dirname, 'public', imagePath);
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
      }
    }
    
    res.json({ message: 'Gallery image deleted successfully', profile });
  } catch (error) {
    console.error('Delete gallery image error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send contact form
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    const profile = await Profile.findOne();
    
    if (!profile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    if (!profile.contactEmail) {
      return res.status(400).json({ error: 'Contact email not configured' });
    }
    
    // Create email transporter
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });
    
    // Email options
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: profile.contactEmail,
      subject: `New message from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
      html: `
        <h3>New message from your website</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    };
    
    // Send email
    await transporter.sendMail(mailOptions);
    
    res.json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error('Send contact form error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});