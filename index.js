import express from "express";
import Datastore from "nedb-promises";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { config } from "./config.js";
import { authenticator } from "otplib";
import qrcode from "qrcode";

const app = express();
app.use(express.json());

const users = Datastore.create("Users.db");
const userRefreshTokens = Datastore.create("UserRefreshTokens.db");

app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, email, password, role} = req.body;
        if (!name || !email || !password) {
            return res.status(422).json({ message: "All fields are required" });
        }
        if (await users.findOne({ email })) {
            return res.status(409).json({ message: "Email already exists" });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword,
            role: role ?? "member",
            '2faEnabled': false,
            "2faSecret": null,
        });

        return res.status(201).json({ 
            message: "User registered successfully",
            id: newUser._id,
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(422).json({ message: "All fields are required" });
        }

        const user = await users.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const accessToken = jwt.sign({ userId: user._id}, config.accessTokenSecret, { subject: 'accessAPI', expiresIn: '1h' });

        const refreshToken = jwt.sign({ userId: user._id}, config.refreshTokenSecret, { subject: 'refreshAPI', expiresIn: '1d' });

        await userRefreshTokens.insert({ refreshToken, userId: user._id });

        return res.status(200).json({ 
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken,
            refreshToken,
            message: "Login successful", id: user._id
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post("/api/auth/refresh-token", async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(422).json({ message: "Refresh token required" });
        }

        // Step 1: Find token in DB
        const tokenData = await userRefreshTokens.findOne({ refreshToken });
        if (!tokenData) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        // Step 2: Verify token
        let decoded;
        try {
            decoded = jwt.verify(refreshToken, config.refreshTokenSecret);
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Refresh token expired' });
            }
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        // Step 3: Verify user still exists
        const user = await users.findOne({ _id: decoded.userId });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Step 4: Generate new tokens
        const newAccessToken = jwt.sign(
            { userId: decoded.userId },
            config.accessTokenSecret,
            { subject: 'accessAPI', expiresIn: '1h' }
        );

        const newRefreshToken = jwt.sign(
            { userId: decoded.userId },
            config.refreshTokenSecret,
            { expiresIn: '7d' }
        );

        // Step 5: Rotate refresh token
        await userRefreshTokens.updateOne(
            { refreshToken },
            { refreshToken: newRefreshToken }
        );

        return res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        console.error("Refresh token error:", error);
        return res.status(500).json({ message: "Server error" });
    }
});
app.get("/api/auth/2fa/generate", ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        // Generate 2FA secret and save it to the user
        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, 'manfra.io', secret);

        await users.update({ _id: req.user.id }, { $set: { "2faSecret": secret } });
        await users.compactDatafile();

        // Generate QR code
        const qrCode = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });

        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Content-Disposition', "attachment; filename='qrcode.png'");
        return res.status(200).type('image/png').send(qrCode);
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.get("/api/users/current", ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        return res.status(200).json({ 
            id: user._id,
            name: user.name,
            email: user.email,
            message: "User found",
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.get("/api/admin", ensureAuthenticated, authorize(['admin']), async (req, res) => {
    return res.status(200).json({ message: "Admin access granted" });
});
app.get("/api/moderator", ensureAuthenticated, authorize(["admin", 'moderator']), async (req, res) => {
    return res.status(200).json({ message: "Only Admins and moderators can access route" });
});

async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization;

    if (!accessToken) {
        return res.status(401).json({ message: "Access token required" });
    }
    try {
        const decoded = jwt.verify(accessToken, config.accessTokenSecret);
        req.user = {id: decoded.userId};
        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: "Access token expired", code: "Access token exxpired" });
        } else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(403).json({ message: "Invalid access token", code: "Invalid access token" });
        } else {
            return res.status(500).json({ message: error.message});
        }
    }    
}

function authorize(roles = []) {
    return async (req, res, next) => {
        const user = await users.findOne({ _id: req.user.id });
        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }
        next();
    }
};

app.post("/api/auth/logout", async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(422).json({ message: "Refresh token required to logout" });
        }

        // Remove refresh token from DB
        await userRefreshTokens.remove({ refreshToken });

        return res.status(200).json({ message: "Logout successful" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});


app.listen(3000, () => {
    console.log("Server is running on port 3000");
});