import express from "express"
import mongoose from "mongoose"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
import path from "path"
import { fileURLToPath } from "url"
import multer from "multer"
import fs from "fs"
import cors from "cors"
import helmet from "helmet"

// Load environment variables
dotenv.config()

// Initialize Express app
const app = express()
const PORT = process.env.PORT || 3000
const DOMAIN = process.env.DOMAIN || ''
const __dirname = path.dirname(fileURLToPath(import.meta.url))

// Middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors())
app.use(helmet({
  contentSecurityPolicy: false // Disable CSP for simplicity in development
}))

// Serve static files
app.use(express.static(path.join(__dirname, "public")))

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "public", "uploads")
const imagesDir = path.join(__dirname, "public", "images")

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

if (!fs.existsSync(imagesDir)) {
  fs.mkdirSync(imagesDir, { recursive: true })
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "public", "uploads"))
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9)
    const ext = path.extname(file.originalname)
    cb(null, file.fieldname + "-" + uniqueSuffix + ext)
  }
})

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    // Accept only images
    if (file.mimetype.startsWith("image/")) {
      cb(null, true)
    } else {
      cb(new Error("Only image files are allowed"))
    }
  }
})

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URL || "")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err))

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
})

const User = mongoose.model("User", userSchema)

// Link Schema
const linkSchema = new mongoose.Schema({
  text: { type: String, required: true },
  url: { type: String, required: true },
  icon: { type: String, default: "link" }
})

// Service Schema
const serviceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  icon: { type: String, default: "star" }
})

// Contact Info Schema
const contactInfoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  value: { type: String, required: true },
  type: { type: String, enum: ['text', 'email', 'phone', 'link'], default: 'text' },
  icon: { type: String, default: "envelope" }
})

// FAQ Schema
const faqSchema = new mongoose.Schema({
  question: { type: String, required: true },
  answer: { type: String, required: true }
})

// Profile Schema - Updated with new fields
const profileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  profileImage: { type: String, required: true },
  logoImage: { type: String, required: true },
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
  galleryImages: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
})

const Profile = mongoose.model("Profile", profileSchema)

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization

    if (!authHeader) {
      return res.status(401).json({ message: "Authorization header missing" })
    }

    if (authHeader.startsWith("Bearer ")) {
      const token = authHeader.split(" ")[1]

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret")
        req.user = decoded
        return next()
      } catch (jwtError) {
        return res.status(401).json({ message: "Invalid token" })
      }
    } else {
      return res.status(401).json({ message: "Invalid authorization format" })
    }
  } catch (error) {
    console.error("Auth error:", error)
    return res.status(500).json({ message: "Authentication error" })
  }
}

// Initialize default profile if none exists
async function initializeDefaultProfile() {
  try {
    const profileCount = await Profile.countDocuments()
    
    if (profileCount === 0) {
      const defaultProfile = new Profile({
        name: "John Doe",
        description: "Welcome to my personal profile! I'm a passionate web developer with expertise in creating responsive and user-friendly websites. Feel free to browse through my work and get in touch if you'd like to collaborate.",
        profileImage: "/images/profile.jpg",
        logoImage: "/images/logo.png",
        backgroundColor: "#ffffff",
        textColor: "#333333",
        accentColor: "#4f46e5",
        galleryBgColor: "#f9fafb",
        servicesBgColor: "#ffffff",
        servicesSectionTitle: "My Services",
        gallerySectionTitle: "My Gallery",
        infoSectionTitle: "Contact Information",
        faqSectionTitle: "Frequently Asked Questions",
        contactSectionTitle: "Contact Me",
        showContactForm: true,
        contactEmail: "admin@example.com",
        links: [
          { text: "GitHub", url: "https://github.com", icon: "github" },
          { text: "LinkedIn", url: "https://linkedin.com", icon: "linkedin" }
        ],
        services: [
          { 
            title: "Web Development", 
            description: "Custom websites and web applications built with the latest technologies.",
            icon: "code"
          },
          { 
            title: "UI/UX Design", 
            description: "User-friendly interfaces that provide a great user experience.",
            icon: "paint-brush"
          },
          { 
            title: "Mobile Apps", 
            description: "Native and cross-platform mobile applications for iOS and Android.",
            icon: "mobile"
          }
        ],
        contactInfo: [
          {
            title: "Email",
            value: "contact@example.com",
            type: "email",
            icon: "envelope"
          },
          {
            title: "Phone",
            value: "+1 (555) 123-4567",
            type: "phone",
            icon: "phone"
          },
          {
            title: "Address",
            value: "123 Main Street, City, Country",
            type: "text",
            icon: "map-marker-alt"
          }
        ],
        faqs: [
          {
            question: "What services do you offer?",
            answer: "I offer web development, UI/UX design, and mobile app development services."
          },
          {
            question: "How can I contact you?",
            answer: "You can use the contact form on this page or email me directly at contact@example.com."
          }
        ],
        galleryImages: [
          "/images/gallery-1.jpg",
          "/images/gallery-2.jpg",
          "/images/gallery-3.jpg"
        ]
      })
      
      await defaultProfile.save()
      console.log("Default profile created")
    }
  } catch (error) {
    console.error("Error initializing default profile:", error)
  }
}

// Initialize default admin user if none exists
async function initializeDefaultAdmin() {
  try {
    const adminCount = await User.countDocuments()
    
    if (adminCount === 0) {
      // Hash password
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || "admin123", salt)
      
      const defaultAdmin = new User({
        email: process.env.ADMIN_EMAIL || "admin@example.com",
        password: hashedPassword
      })
      
      await defaultAdmin.save()
      console.log("Default admin user created")
    }
  } catch (error) {
    console.error("Error initializing default admin:", error)
  }
}

// API Routes

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body

    // Find user
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET || "your_jwt_secret", {
      expiresIn: "1d",
    })

    res.json({
      message: "Login successful",
      token
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ message: "Login failed", error: error.message })
  }
})

// Get profile data (public)
app.get("/api/profile", async (req, res) => {
  try {
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    res.json(profile)
  } catch (error) {
    console.error("Error fetching profile:", error)
    res.status(500).json({ message: "Failed to fetch profile", error: error.message })
  }
})

// Update profile (authenticated)
app.put("/api/profile", authenticate, upload.single("profileImage"), async (req, res) => {
  try {
    const { 
      name, 
      description, 
      backgroundColor, 
      textColor, 
      accentColor, 
      contactEmail,
      galleryBgColor,
      servicesBgColor,
      showContactForm,
      servicesSectionTitle,
      gallerySectionTitle,
      infoSectionTitle,
      faqSectionTitle,
      contactSectionTitle
    } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Update fields
    if (name) profile.name = name
    if (description) profile.description = description
    
    // Update section titles
    if (servicesSectionTitle) profile.servicesSectionTitle = servicesSectionTitle
    if (gallerySectionTitle) profile.gallerySectionTitle = gallerySectionTitle
    if (infoSectionTitle) profile.infoSectionTitle = infoSectionTitle
    if (faqSectionTitle) profile.faqSectionTitle = faqSectionTitle
    if (contactSectionTitle) profile.contactSectionTitle = contactSectionTitle
    
    // Update colors if provided
    if (backgroundColor) profile.backgroundColor = backgroundColor
    if (textColor) profile.textColor = textColor
    if (accentColor) profile.accentColor = accentColor
    if (galleryBgColor) profile.galleryBgColor = galleryBgColor
    if (servicesBgColor) profile.servicesBgColor = servicesBgColor
    
    // Update contact settings
    if (contactEmail) profile.contactEmail = contactEmail
    if (showContactForm !== undefined) {
      profile.showContactForm = showContactForm === 'true' || showContactForm === true
    }
    
    // Update profile image if provided
    if (req.file) {
      // Remove old file if it's not a default image
      if (profile.profileImage && !profile.profileImage.startsWith("/images/")) {
        const oldPath = path.join(__dirname, "public", profile.profileImage)
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath)
        }
      }
      
      profile.profileImage = `/uploads/${req.file.filename}`
    }
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Profile updated successfully",
      profile
    })
  } catch (error) {
    console.error("Error updating profile:", error)
    res.status(500).json({ message: "Failed to update profile", error: error.message })
  }
})

// Update logo (authenticated)
app.put("/api/logo", authenticate, upload.single("logoImage"), async (req, res) => {
  try {
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Update logo image if provided
    if (req.file) {
      // Remove old file if it's not a default image
      if (profile.logoImage && !profile.logoImage.startsWith("/images/")) {
        const oldPath = path.join(__dirname, "public", profile.logoImage)
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath)
        }
      }
      
      profile.logoImage = `/uploads/${req.file.filename}`
    }
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Logo updated successfully",
      profile
    })
  } catch (error) {
    console.error("Error updating logo:", error)
    res.status(500).json({ message: "Failed to update logo", error: error.message })
  }
})

// Add link (authenticated)
app.post("/api/links", authenticate, async (req, res) => {
  try {
    const { text, url, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Add new link
    profile.links.push({
      text,
      url,
      icon: icon || "link"
    })
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Link added successfully",
      link: profile.links[profile.links.length - 1],
      profile
    })
  } catch (error) {
    console.error("Error adding link:", error)
    res.status(500).json({ message: "Failed to add link", error: error.message })
  }
})

// Update link (authenticated)
app.put("/api/links/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    const { text, url, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.links.length) {
      return res.status(400).json({ message: "Invalid link index" })
    }
    
    // Update link
    if (text) profile.links[index].text = text
    if (url) profile.links[index].url = url
    if (icon) profile.links[index].icon = icon
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Link updated successfully",
      link: profile.links[index],
      profile
    })
  } catch (error) {
    console.error("Error updating link:", error)
    res.status(500).json({ message: "Failed to update link", error: error.message })
  }
})

// Delete link (authenticated)
app.delete("/api/links/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.links.length) {
      return res.status(400).json({ message: "Invalid link index" })
    }
    
    // Remove link
    profile.links.splice(index, 1)
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Link deleted successfully",
      profile
    })
  } catch (error) {
    console.error("Error deleting link:", error)
    res.status(500).json({ message: "Failed to delete link", error: error.message })
  }
})

// Add service (authenticated)
app.post("/api/services", authenticate, async (req, res) => {
  try {
    const { title, description, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Add new service
    profile.services.push({
      title,
      description,
      icon: icon || "star"
    })
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Service added successfully",
      service: profile.services[profile.services.length - 1],
      profile
    })
  } catch (error) {
    console.error("Error adding service:", error)
    res.status(500).json({ message: "Failed to add service", error: error.message })
  }
})

// Update service (authenticated)
app.put("/api/services/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    const { title, description, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    

    if (index < 0 || index >= profile.services.length) {
      return res.status(400).json({ message: "Invalid service index" })
    }
    
    if (title) profile.services[index].title = title
    if (description) profile.services[index].description = description
    if (icon) profile.services[index].icon = icon
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Service updated successfully",
      service: profile.services[index],
      profile
    })
  } catch (error) {
    console.error("Error updating service:", error)
    res.status(500).json({ message: "Failed to update service", error: error.message })
  }
})

// Delete service (authenticated)
app.delete("/api/services/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.services.length) {
      return res.status(400).json({ message: "Invalid service index" })
    }
    
    // Remove service
    profile.services.splice(index, 1)
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Service deleted successfully",
      profile
    })
  } catch (error) {
    console.error("Error deleting service:", error)
    res.status(500).json({ message: "Failed to delete service", error: error.message })
  }
})

// Add contact info (authenticated)
app.post("/api/contactInfo", authenticate, async (req, res) => {
  try {
    const { title, value, type, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Add new contact info
    profile.contactInfo.push({
      title,
      value,
      type: type || 'text',
      icon: icon || "envelope"
    })
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Contact info added successfully",
      contactInfo: profile.contactInfo[profile.contactInfo.length - 1],
      profile
    })
  } catch (error) {
    console.error("Error adding contact info:", error)
    res.status(500).json({ message: "Failed to add contact info", error: error.message })
  }
})

// Update contact info (authenticated)
app.put("/api/contactInfo/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    const { title, value, type, icon } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.contactInfo.length) {
      return res.status(400).json({ message: "Invalid contact info index" })
    }
    
    // Update contact info
    if (title) profile.contactInfo[index].title = title
    if (value) profile.contactInfo[index].value = value
    if (type) profile.contactInfo[index].type = type
    if (icon) profile.contactInfo[index].icon = icon
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Contact info updated successfully",
      contactInfo: profile.contactInfo[index],
      profile
    })
  } catch (error) {
    console.error("Error updating contact info:", error)
    res.status(500).json({ message: "Failed to update contact info", error: error.message })
  }
})

// Delete contact info (authenticated)
app.delete("/api/contactInfo/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.contactInfo.length) {
      return res.status(400).json({ message: "Invalid contact info index" })
    }
    
    // Remove contact info
    profile.contactInfo.splice(index, 1)
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Contact info deleted successfully",
      profile
    })
  } catch (error) {
    console.error("Error deleting contact info:", error)
    res.status(500).json({ message: "Failed to delete contact info", error: error.message })
  }
})

// Add FAQ (authenticated)
app.post("/api/faqs", authenticate, async (req, res) => {
  try {
    const { question, answer } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Add new FAQ
    profile.faqs.push({
      question,
      answer
    })
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "FAQ added successfully",
      faq: profile.faqs[profile.faqs.length - 1],
      profile
    })
  } catch (error) {
    console.error("Error adding FAQ:", error)
    res.status(500).json({ message: "Failed to add FAQ", error: error.message })
  }
})

// Update FAQ (authenticated)
app.put("/api/faqs/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    const { question, answer } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.faqs.length) {
      return res.status(400).json({ message: "Invalid FAQ index" })
    }
    
    // Update FAQ
    if (question) profile.faqs[index].question = question
    if (answer) profile.faqs[index].answer = answer
    
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "FAQ updated successfully",
      faq: profile.faqs[index],
      profile
    })
  } catch (error) {
    console.error("Error updating FAQ:", error)
    res.status(500).json({ message: "Failed to update FAQ", error: error.message })
  }
})

// Delete FAQ (authenticated)
app.delete("/api/faqs/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.faqs.length) {
      return res.status(400).json({ message: "Invalid FAQ index" })
    }
    
    // Remove FAQ
    profile.faqs.splice(index, 1)
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "FAQ deleted successfully",
      profile
    })
  } catch (error) {
    console.error("Error deleting FAQ:", error)
    res.status(500).json({ message: "Failed to delete FAQ", error: error.message })
  }
})

// Send contact email (public)
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body
    
    if (!name || !email || !message) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if contact form is enabled
    if (!profile.showContactForm) {
      return res.status(403).json({ message: "Contact form is disabled" })
    }
    
    const toEmail = profile.contactEmail || "admin@example.com"
    
    // Send email using external service
    const response = await fetch('https://2.vil0.com/send-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        "from": "Custom Web Contact Form",  
        "replyTo": email,
        "to": toEmail,
        "subject": `New contact from ${name}`,
        "body": `
          <h1>New Contact Message</h1>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Message:</strong></p>
          <p>${message}</p>
        `
      })
    })
    
    if (!response.ok) {
      throw new Error('Failed to send email')
    }
    
    res.json({
      message: "Message sent successfully"
    })
  } catch (error) {
    console.error("Error sending contact email:", error)
    res.status(500).json({ message: "Failed to send message", error: error.message })
  }
})

// Upload gallery images (authenticated)
app.post("/api/gallery", authenticate, upload.array("images", 10), async (req, res) => {
  try {
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Get uploaded file paths
    const uploadedImages = req.files.map(file => `/uploads/${file.filename}`)
    
    // Add to gallery
    profile.galleryImages = [...profile.galleryImages, ...uploadedImages]
    profile.updatedAt = new Date()
    
    await profile.save()
    
    res.json({
      message: "Images uploaded successfully",
      images: uploadedImages,
      profile
    })
  } catch (error) {
    console.error("Error uploading gallery images:", error)
    res.status(500).json({ message: "Failed to upload images", error: error.message })
  }
})

// Delete gallery image (authenticated)
app.delete("/api/gallery/:index", authenticate, async (req, res) => {
  try {
    const { index } = req.params
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Check if index is valid
    if (index < 0 || index >= profile.galleryImages.length) {
      return res.status(400).json({ message: "Invalid image index" })
    }
    
    // Get image path
    const imagePath = profile.galleryImages[index]
    
    // Remove from array
    profile.galleryImages.splice(index, 1)
    profile.updatedAt = new Date()
    
    await profile.save()
    
    // Delete file if it's not a default image
    if (imagePath && !imagePath.startsWith("/images/")) {
      const fullPath = path.join(__dirname, "public", imagePath)
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath)
      }
    }
    
    res.json({
      message: "Image deleted successfully",
      profile
    })
  } catch (error) {
    console.error("Error deleting gallery image:", error)
    res.status(500).json({ message: "Failed to delete image", error: error.message })
  }
})

// Route for all HTML pages
app.get(["/", "/custom-web/login", "/custom-web/admin"], (req, res) => {
  const requestPath = req.path;
  
  if (requestPath === "/custom-web/login") {
    res.sendFile(path.join(__dirname, "public", "login.html"));
  } else if (requestPath === "/custom-web/admin") {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
  } else {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

// 404 route
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

// Start server
async function startServer() {
  try {
    // Initialize default data
    await initializeDefaultProfile();
    await initializeDefaultAdmin();
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Application URL: https://${DOMAIN}`);
      console.log(`Admin login: https://${DOMAIN}/custom-web/login`);
    });
  } catch (error) {
    console.error("Server startup error:", error);
  }
}

startServer();

export default app;