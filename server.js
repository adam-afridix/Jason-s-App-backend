const express = require("express");
const cors = require("cors");
const multer = require("multer");
const { google } = require("googleapis");
const dotenv = require("dotenv");
const stream = require("stream");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration - ONLY ONCE
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://aquamarine-semolina-dd6e68.netlify.app'
  ],
  credentials: true
}));

// Middleware
app.use(express.json());

// Configure multer for file uploads (store in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
  },
});

// ============================================
// 🔐 AUTHENTICATION MIDDLEWARE
// ============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Please login.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ============================================
// 🔑 LOGIN ROUTE
// ============================================
app.post("/api/auth/login", async (req, res) => {
  const { username, password, rememberMe } = req.body;

  try {
    // Check username
    if (username !== process.env.ADMIN_USERNAME) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check password (plain text comparison for simplicity)
    // For production, use bcrypt.compare() with hashed passwords
    if (password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Create token
    const expiresIn = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { username: username },
      process.env.JWT_SECRET,
      { expiresIn: expiresIn }
    );

    console.log(`✅ User "${username}" logged in successfully`);

    res.json({ 
      success: true,
      token: token,
      message: 'Login successful' 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ============================================
// 🔓 VERIFY TOKEN ROUTE
// ============================================
app.get("/api/auth/verify", authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// OAuth2 configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REACT_APP_API_URL
);

// Token file path
const TOKEN_PATH = path.join(__dirname, "google-token.json");

// Load saved token
if (fs.existsSync(TOKEN_PATH)) {
  const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oauth2Client.setCredentials(token);
  console.log("✅ OAuth token loaded from file");
  console.log("   Token expiry:", token.expiry_date ? new Date(token.expiry_date).toISOString() : "N/A");
  console.log("   Has refresh token:", !!token.refresh_token);
} else {
  console.log("⚠️  No OAuth token file found at:", TOKEN_PATH);
}

// Save token
function saveToken(token) {
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(token));
  console.log("✅ Token saved to file");
}

const drive = google.drive({ version: "v3", auth: oauth2Client });

// UPLOAD FILE TO GOOGLE DRIVE
async function uploadFileToGoogleDrive(file) {
  console.log(`\n📄 Uploading file: ${file.originalname}`);
  console.log(`   Size: ${(file.size / 1024 / 1024).toFixed(2)} MB`);
  console.log(`   Type: ${file.mimetype}`);
  
  const fileMetadata = {
    name: file.originalname,
    parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
  };

  const media = {
    mimeType: file.mimetype,
    body: stream.Readable.from(file.buffer),
  };

  try {
    console.log(`   ⏳ Calling Google Drive API...`);
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: media,
      fields: "id, name, webViewLink, webContentLink",
      supportsAllDrives: true,
    });

    console.log(`   ✅ Successfully uploaded: ${response.data.name}`);
    console.log(`   📁 File ID: ${response.data.id}`);
    return response.data;
  } catch (error) {
    console.error(`\n   ❌ Error uploading ${file.originalname}:`);
    console.error(`   Error type: ${error.name}`);
    console.error(`   Error message: ${error.message}`);
    console.error(`   Error code: ${error.code}`);
    
    if (error.response) {
      console.error(`   API Status: ${error.response.status}`);
      console.error(`   API Data:`, JSON.stringify(error.response.data, null, 2));
    }
    
    throw error;
  }
}

// Health check
app.get("/", (req, res) => {
  res.json({
    message: "Backend server is running!",
    status: "OK",
    authenticated: !!oauth2Client.credentials.access_token,
  });
});

// Step 1: Get OAuth URL (🔒 PROTECTED)
app.get("/api/auth/url", authenticateToken, (req, res) => {
  console.log("\n🔗 OAuth URL requested by:", req.user?.username);
  
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/drive.file"],
    prompt: "consent",  // This forces re-consent to get a fresh token
  });
  
  console.log("✅ Authorization URL generated");
  console.log("   User should visit this URL to authorize");
  console.log("   This will force re-authentication and get a new token");
  
  res.json({ authUrl });
});

// Force revoke and reconnect (🔒 PROTECTED)
app.post("/api/auth/revoke", authenticateToken, async (req, res) => {
  console.log("\n🔓 Token revocation requested by:", req.user?.username);
  
  try {
    // Clear the token file
    if (fs.existsSync(TOKEN_PATH)) {
      fs.unlinkSync(TOKEN_PATH);
      console.log("✅ Token file deleted");
    }
    
    // Clear credentials from client
    oauth2Client.setCredentials({});
    console.log("✅ Credentials cleared from OAuth client");
    
    res.json({ 
      success: true, 
      message: "Token revoked successfully. Please reconnect to Google Drive." 
    });
  } catch (error) {
    console.error("❌ Error revoking token:", error);
    res.status(500).json({ 
      success: false, 
      error: "Failed to revoke token",
      details: error.message 
    });
  }
});

// Step 2: OAuth Callback
app.get("/api/auth/callback", async (req, res) => {
  console.log("\n========================================");
  console.log("🔐 OAuth Callback Received");
  console.log("========================================");
  
  const { code } = req.query;

  if (!code) {
    console.error("❌ No authorization code in request");
    return res.status(400).send("No authorization code provided");
  }

  console.log("✅ Authorization code received");
  console.log("⏳ Exchanging code for tokens...");

  try {
    const { tokens } = await oauth2Client.getToken(code);
    console.log("✅ Tokens received from Google");
    console.log("   Access token:", tokens.access_token ? "Yes" : "No");
    console.log("   Refresh token:", tokens.refresh_token ? "Yes" : "No");
    console.log("   Expires at:", tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : "N/A");
    
    oauth2Client.setCredentials(tokens);
    saveToken(tokens);
    
    console.log("✅ Tokens saved successfully");
    console.log("========================================\n");

    res.send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1 style="color: #22c55e;">✅ Authentication Successful!</h1>
          <p>You can close this window and return to your app.</p>
          <p style="color: #666; font-size: 14px; margin-top: 20px;">Token saved and ready to use.</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("\n❌ OAuth Callback Error:");
    console.error("Error name:", error.name);
    console.error("Error message:", error.message);
    console.error("Error stack:", error.stack);
    console.error("========================================\n");
    
    res.status(500).send(`
      <html>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h1 style="color: #ef4444;">❌ Authentication Failed</h1>
          <p>Error: ${error.message}</p>
          <p style="color: #666; font-size: 14px; margin-top: 20px;">Check backend console for details.</p>
        </body>
      </html>
    `);
  }
});

// Auth status (🔒 PROTECTED)
app.get("/api/auth/status", authenticateToken, (req, res) => {
  const authenticated = !!oauth2Client.credentials.access_token;
  const expiresAt = oauth2Client.credentials.expiry_date;
  const isExpired = expiresAt && expiresAt < Date.now();
  
  console.log("\n🔍 Auth Status Check:");
  console.log("   User:", req.user?.username);
  console.log("   Authenticated:", authenticated);
  console.log("   Expires at:", expiresAt ? new Date(expiresAt).toISOString() : "N/A");
  console.log("   Is expired:", isExpired);
  console.log("   Has refresh token:", !!oauth2Client.credentials.refresh_token);
  
  // If expired, treat as not authenticated
  const actuallyAuthenticated = authenticated && !isExpired;
  
  res.json({
    authenticated: actuallyAuthenticated,  // Changed: only true if not expired
    expiresAt: expiresAt,
    isExpired: isExpired,
    hasRefreshToken: !!oauth2Client.credentials.refresh_token,
    needsReauth: isExpired || !authenticated,
  });
});

// ============================================
// UPLOAD FILES WITH METADATA (🔒 PROTECTED)
// ============================================
app.post(
  "/api/upload",
  authenticateToken, // 👈 Added authentication
  upload.fields([
    { name: "files", maxCount: 50 },
    { name: "metadata", maxCount: 1 },
  ]),
  async (req, res) => {
    console.log("\n========================================");
    console.log("📤 UPLOAD REQUEST RECEIVED");
    console.log("========================================");
    console.log("👤 User:", req.user?.username);
    console.log("📅 Time:", new Date().toISOString());
    
    try {
      // Check OAuth token status
      console.log("\n🔐 Checking OAuth credentials...");
      console.log("Access Token exists:", !!oauth2Client.credentials.access_token);
      console.log("Refresh Token exists:", !!oauth2Client.credentials.refresh_token);
      console.log("Token expiry:", oauth2Client.credentials.expiry_date ? new Date(oauth2Client.credentials.expiry_date).toISOString() : "N/A");
      
      if (!oauth2Client.credentials.access_token) {
        console.error("❌ No OAuth access token found!");
        return res.status(401).json({
          error: "Not authenticated",
          message: "Authenticate with Google first",
        });
      }

      const files = req.files["files"] || [];
      const metadataFile = req.files["metadata"] ? req.files["metadata"][0] : null;

      console.log("\n📦 Files received:");
      console.log("- Main files:", files.length);
      console.log("- Metadata file:", metadataFile ? metadataFile.originalname : "None");

      if (files.length === 0) {
        console.error("❌ No files in request");
        return res.status(400).json({ error: "No files uploaded" });
      }

      console.log(`\n📤 Starting upload of ${files.length} file(s)...`);
      
      const uploadedFiles = [];

      // Upload metadata file FIRST if it exists
      if (metadataFile) {
        console.log("\n📝 Uploading metadata file:", metadataFile.originalname);
        console.log(`   Size: ${(metadataFile.size / 1024).toFixed(2)} KB`);
        
        const metadataFileMetadata = {
          name: metadataFile.originalname,
          parents: [process.env.GOOGLE_DRIVE_FOLDER_ID],
        };

        const metadataMedia = {
          mimeType: "application/json",
          body: stream.Readable.from(metadataFile.buffer),
        };

        console.log(`   ⏳ Calling Google Drive API for metadata...`);
        const metadataResponse = await drive.files.create({
          requestBody: metadataFileMetadata,
          media: metadataMedia,
          fields: "id, name, webViewLink, webContentLink",
          supportsAllDrives: true,
        });

        uploadedFiles.push({
          name: metadataFile.originalname,
          id: metadataResponse.data.id,
          webViewLink: metadataResponse.data.webViewLink,
          webContentLink: metadataResponse.data.webContentLink,
          type: "metadata",
        });

        console.log("   ✅ Metadata file uploaded:", metadataResponse.data.name);
        console.log("   📁 File ID:", metadataResponse.data.id);
      }

      // Upload all other files
      const fileUploadPromises = files.map((file) =>
        uploadFileToGoogleDrive(file)
      );

      const fileResults = await Promise.all(fileUploadPromises);
      
      fileResults.forEach(result => {
        uploadedFiles.push({
          ...result,
          type: "file"
        });
      });

      console.log(`✅ Successfully uploaded ${uploadedFiles.length} file(s) to Google Drive`);

      res.json({
        message: "Files uploaded successfully",
        files: uploadedFiles,
        count: uploadedFiles.length,
      });
    } catch (error) {
      console.error("\n❌❌❌ UPLOAD ERROR ❌❌❌");
      console.error("Error name:", error.name);
      console.error("Error message:", error.message);
      console.error("Error code:", error.code);
      
      if (error.response) {
        console.error("API Response Status:", error.response.status);
        console.error("API Response Data:", JSON.stringify(error.response.data, null, 2));
      }
      
      if (error.message.includes("invalid_grant")) {
        console.error("\n🔴 OAUTH TOKEN EXPIRED OR INVALID!");
        console.error("💡 Solution: Re-authenticate with Google Drive");
        console.error("   Visit: /api/auth/url to get the authorization URL");
      }
      
      console.error("Full error stack:", error.stack);
      console.error("========================================\n");
      
      res.status(500).json({
        error: "Failed to upload files",
        details: error.message,
        code: error.code,
        needsReauth: error.message.includes("invalid_grant"),
      });
    }
  }
);

// LIST FILES (🔒 PROTECTED)
app.get("/api/files", authenticateToken, async (req, res) => {
  try {
    if (!oauth2Client.credentials.access_token) {
      return res.status(401).json({
        error: "Not authenticated",
        message: "Authenticate first",
      });
    }

    const response = await drive.files.list({
      q: `'${process.env.GOOGLE_DRIVE_FOLDER_ID}' in parents and trashed=false`,
      fields: "files(id, name, mimeType, createdTime, webViewLink)",
      orderBy: "createdTime desc",
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
    });

    res.json({
      files: response.data.files,
      count: response.data.files.length,
    });
  } catch (error) {
    console.error("Error fetching files:", error);
    res.status(500).json({
      error: "Failed to fetch files",
      details: error.message,
    });
  }
});

// ============================================
// n8n WEBHOOK ROUTES (🔒 PROTECTED)
// ============================================

// Route to send YouTube link to n8n (🔒 PROTECTED)
app.post("/api/n8n/youtube-link", authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "No URL provided" });
    }

    if (!url.includes("youtube.com") && !url.includes("youtu.be")) {
      return res.status(400).json({ error: "Invalid YouTube URL" });
    }

    console.log("Sending to n8n:", url);

    const response = await fetch(process.env.N8N_YOUTUBE_LINK_WEBHOOK, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "youtube",
        url: url,
        timestamp: new Date().toISOString(),
      }),
    });

    console.log("n8n response status:", response.status);

    if (!response.ok) {
      throw new Error(`n8n webhook failed: ${response.status}`);
    }

    const responseText = await response.text();
    console.log("n8n raw response:", responseText);

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.warn("n8n returned non-JSON response:", responseText);
      return res.json({
        success: true,
        message: "YouTube link sent to n8n successfully",
        n8nResponse: {
          raw: responseText,
          note: "n8n webhook accepted the data (non-JSON response)",
        },
      });
    }

    if (Array.isArray(result)) {
      result = result[0];
    }

    res.json({
      success: true,
      message: "YouTube link sent to n8n successfully",
      n8nResponse: result,
    });
  } catch (error) {
    console.error("Error sending to n8n:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send to n8n",
      details: error.message,
    });
  }
});

// Paste text route (🔒 PROTECTED)
app.post("/api/n8n/paste-text", authenticateToken, async (req, res) => {
  try {
    const { content, metadata } = req.body;

    if (!content) {
      return res.status(400).json({ error: "No content provided" });
    }

    console.log("Sending text to n8n, length:", content.length);
    console.log("Metadata received:", metadata);

    // Build the payload with all data
    const payload = {
      type: "text",
      content: content,
      wordCount: content.split(/\s+/).filter((word) => word.length > 0).length,
      characterCount: content.length,
      timestamp: new Date().toISOString(),
    };

    // Add metadata if provided
    if (metadata) {
      payload.metadata = {
        title: metadata.title || "",
        description: metadata.description || "",
        category: metadata.category || "",
        publishedDate: metadata.publishedDate || "",
        tags: Array.isArray(metadata.tags) ? metadata.tags : [],
      };
    }

    console.log("Full payload to n8n:", JSON.stringify(payload, null, 2));

    const response = await fetch(process.env.N8N_PASTE_TEXT_WEBHOOK, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    console.log("n8n response status:", response.status);

    if (!response.ok) {
      throw new Error(`n8n webhook failed: ${response.status}`);
    }

    const responseText = await response.text();
    console.log("n8n raw response:", responseText);

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.warn("n8n returned non-JSON response:", responseText);
      return res.json({
        success: true,
        message: "Text and metadata sent to n8n successfully",
        n8nResponse: {
          raw: responseText,
          note: "n8n webhook accepted the data (non-JSON response)",
        },
      });
    }

    if (Array.isArray(result)) {
      result = result[0];
    }

    res.json({
      success: true,
      message: "Text and metadata sent to n8n successfully",
      n8nResponse: result,
    });
  } catch (error) {
    console.error("Error sending to n8n:", error);
    res.status(500).json({
      success: false,
      error: "Failed to send to n8n",
      details: error.message,
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log("\n========================================");
  console.log("🚀 BACKEND SERVER STARTED");
  console.log("========================================");
  console.log(`✅ Server running on: http://localhost:${PORT}`);
  console.log(`📅 Started at: ${new Date().toISOString()}`);
  console.log("\n📋 Configuration:");
  console.log(`   Google Drive Folder ID: ${process.env.GOOGLE_DRIVE_FOLDER_ID}`);
  console.log(`   n8n Paste Text Webhook: ${process.env.N8N_PASTE_TEXT_WEBHOOK ? "✅ Configured" : "❌ Missing"}`);
  console.log(`   n8n YouTube Link Webhook: ${process.env.N8N_YOUTUBE_LINK_WEBHOOK ? "✅ Configured" : "❌ Missing"}`);
  console.log(`   Admin Username: ${process.env.ADMIN_USERNAME}`);
  console.log(`   JWT Secret: ${process.env.JWT_SECRET ? "✅ Set" : "❌ Missing"}`);

  console.log("\n🔐 Google OAuth Status:");
  if (oauth2Client.credentials.access_token) {
    const expiresAt = oauth2Client.credentials.expiry_date;
    const isExpired = expiresAt && expiresAt < Date.now();
    
    console.log("   Status: ✅ Authenticated with Google Drive");
    console.log("   Token expires:", expiresAt ? new Date(expiresAt).toISOString() : "Unknown");
    console.log("   Is expired:", isExpired ? "⚠️  YES - Need to re-authenticate" : "✅ No");
    console.log("   Has refresh token:", oauth2Client.credentials.refresh_token ? "✅ Yes" : "⚠️  No");
    
    if (isExpired) {
      console.log("\n⚠️  WARNING: OAuth token is expired!");
      console.log(`   Visit: http://localhost:${PORT}/api/auth/url to re-authenticate`);
    }
  } else {
    console.log("   Status: ❌ Not authenticated");
    console.log(`   Action needed: Visit http://localhost:${PORT}/api/auth/url to authenticate`);
  }

  console.log("\n🚀 Ready for:");
  console.log("   • JWT Authentication");
  console.log("   • File uploads to Google Drive");
  console.log("   • n8n webhook integration");
  console.log("========================================\n");
});