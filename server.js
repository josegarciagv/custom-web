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
const DOMAIN = process.env.DOMAIN || 'custom-web-production.up.railway.app'
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
  .connect(process.env.MONGO_URL || "mongodb://localhost:27017/custom-web")
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

// Profile Schema - Updated with new fields
const profileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  profileImage: { type: String, required: true },
  logoImage: { type: String, required: true },
  buttonText: { type: String, required: true },
  buttonUrl: { type: String, required: true },
  galleryImages: [{ type: String }],
  // New fields
  backgroundColor: { type: String, default: "#ffffff" },
  textColor: { type: String, default: "#333333" },
  accentColor: { type: String, default: "#4f46e5" },
  links: [linkSchema],
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
        buttonText: "Visit My Website",
        buttonUrl: "https://example.com",
        backgroundColor: "#ffffff",
        textColor: "#333333",
        accentColor: "#4f46e5",
        links: [
          { text: "GitHub", url: "https://github.com", icon: "github" },
          { text: "LinkedIn", url: "https://linkedin.com", icon: "linkedin" }
        ],
        galleryImages: [
        
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
    const { name, description, backgroundColor, textColor, accentColor } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Update fields
    profile.name = name || profile.name
    profile.description = description || profile.description
    
    // Update colors if provided
    if (backgroundColor) profile.backgroundColor = backgroundColor
    if (textColor) profile.textColor = textColor
    if (accentColor) profile.accentColor = accentColor
    
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

// Update button settings (authenticated)
app.put("/api/button", authenticate, upload.single("logoImage"), async (req, res) => {
  try {
    const { buttonText, buttonUrl } = req.body
    
    const profile = await Profile.findOne()
    
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" })
    }
    
    // Update fields
    profile.buttonText = buttonText || profile.buttonText
    profile.buttonUrl = buttonUrl || profile.buttonUrl
    
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
      message: "Button settings updated successfully",
      profile
    })
  } catch (error) {
    console.error("Error updating button settings:", error)
    res.status(500).json({ message: "Failed to update button settings", error: error.message })
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

// Route for all HTML pages - CORRECTED PATHS
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

// 404 route - CORRECTED PATH
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