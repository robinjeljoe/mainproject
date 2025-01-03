const express = require('express');
const { google } = require('googleapis');
const fs = require('fs').promises;
const path = require('path');
const app = express();
require('dotenv').config();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// OAuth2 configuration
const oauth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    'http://localhost:3000/auth/google/callback'
);

const TOKEN_PATH = path.join(__dirname, 'token.json');
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

// Token Management
async function saveToken(token) {
    await fs.writeFile(TOKEN_PATH, JSON.stringify(token));
}

async function loadToken() {
    try {
        const content = await fs.readFile(TOKEN_PATH);
        return JSON.parse(content);
    } catch {
        return null;
    }
}

// Authentication Routes
app.get('/auth/google', (req, res) => {
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES
    });
    res.redirect(authUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    try {
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        await saveToken(tokens);
        res.redirect('/emails.html');
    } catch (error) {
        console.error('Error getting tokens:', error);
        res.redirect('/login.html');
    }
});

// Middleware to check and refresh authentication
async function authenticateRequest(req, res, next) {
    try {
        const token = await loadToken();
        if (!token) {
            return res.status(401).redirect('/auth/google');
        }

        oauth2Client.setCredentials(token);

        // Check if token needs refresh
        if (token.expiry_date && token.expiry_date < Date.now()) {
            const { credentials } = await oauth2Client.refreshAccessToken();
            await saveToken(credentials);
            oauth2Client.setCredentials(credentials);
        }

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(401).redirect('/auth/google');
    }
}

// Gmail API Routes
app.get('/api/emails', authenticateRequest, async (req, res) => {
    try {
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const response = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 10
        });

        const emails = await Promise.all(response.data.messages.map(async (message) => {
            const email = await gmail.users.messages.get({
                userId: 'me',
                id: message.id
            });

            const headers = email.data.payload.headers;
            return {
                id: message.id,
                sender: headers.find(h => h.name === 'From')?.value || '',
                subject: headers.find(h => h.name === 'Subject')?.value || '',
                timestamp: email.data.internalDate
            };
        }));

        res.json(emails);
    } catch (error) {
        console.error('Email fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

app.get('/auth/logout', async (req, res) => {
    try {
        await fs.unlink(TOKEN_PATH);
        res.redirect('/login.html');
    } catch {
        res.redirect('/login.html');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});