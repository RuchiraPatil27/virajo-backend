require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

// Optional nodemailer - won't crash if not installed
let nodemailer;
try {
    nodemailer = require('nodemailer');
} catch (err) {
    console.log('Nodemailer not installed - email features disabled');
}

const app = express();
const PORT = process.env.PORT || 10000;

// ===== Middleware =====
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
        'https://virajo.world', 
        'https://www.virajo.world', 
        'http://localhost:10000', 
        'http://localhost:10000'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ===== MongoDB Connection =====
if (!process.env.MONGO_URI) {
    console.error("MONGO_URI environment variable is not set!");
    console.log("Please create a .env file with: MONGO_URI=your_connection_string");
    process.exit(1);
}

if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET environment variable is not set!");
    process.exit(1);
}

// Enhanced MongoDB connection with better error handling
const connectMongoDB = async () => {
    const maxRetries = 3;
    let retryCount = 0;
    
    while (retryCount < maxRetries) {
        try {
            console.log(`🔄 MongoDB connection attempt ${retryCount + 1}/${maxRetries}`);
            
            const options = {
                serverSelectionTimeoutMS: 15000,
                connectTimeoutMS: 15000,
                socketTimeoutMS: 45000,
                maxPoolSize: 10,
                retryWrites: true,
                w: 'majority',
                authSource: 'admin',
                ssl: true,
            };
            
            await mongoose.connect(process.env.MONGO_URI, options);
            
            // Test the connection
            await mongoose.connection.db.admin().ping();
            
            console.log('✅ MongoDB Atlas connected successfully!');
            console.log(`📊 Database: ${mongoose.connection.db.databaseName}`);
            console.log(`🖥️  Host: ${mongoose.connection.host}`);
            
            return true;
            
        } catch (error) {
            retryCount++;
            console.log(`❌ Connection attempt ${retryCount} failed:`, error.message);
            
            if (retryCount === maxRetries) {
                console.log('🚫 All connection attempts failed. Using fallback storage.');
                
                // Initialize fallback storage
                global.mongoFallback = {
                    users: new Map(),
                    templates: new Map(),
                    posts: new Map(),
                    connected: false
                };
                
                return false;
            }
            
            // Wait before retry
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
};

// Initialize connection
connectMongoDB().then(connected => {
    if (connected) {
        console.log('Database ready for operations');
    } else {
        console.log('Running in fallback mode - data will be lost on restart');
    }
});

// ===== Enhanced Email Configuration =====
let emailTransporter;

if (nodemailer && process.env.EMAIL_USER && process.env.EMAIL_APP_PASSWORD) {
    try {
        const emailConfig = {
            service: process.env.EMAIL_SERVICE || 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_APP_PASSWORD
            }
        };

        emailTransporter = nodemailer.createTransporter(emailConfig);
        
        emailTransporter.verify((error, success) => {
            if (error) {
                console.log('Email verification failed:', error.message);
            } else {
                console.log('Email server ready');
            }
        });
    } catch (err) {
        console.log('Email setup failed:', err.message);
    }
}

// Enhanced Email Templates
const emailTemplates = {
    passwordReset: (resetUrl, userFirstName) => ({
        subject: 'Password Reset Request - Virajo Studio',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #ffffff 0%, #fef2f2 100%); border: 2px solid #dc2626; border-radius: 15px; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Password Reset</h1>
                    <p style="color: #fecaca; margin: 10px 0 0 0;">Virajo Social Studio</p>
                </div>
                <div style="padding: 40px;">
                    <p style="color: #7f1d1d; font-size: 16px;">Hello ${userFirstName || 'User'},</p>
                    <p style="color: #7f1d1d; line-height: 1.6;">You requested a password reset for your Virajo Studio account. Click the button below to create a new password:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); color: white; padding: 15px 30px; border-radius: 25px; text-decoration: none; font-weight: bold; display: inline-block;">Reset My Password</a>
                    </div>
                    <p style="color: #7f1d1d; font-size: 14px;">This link expires in 1 hour for security reasons.</p>
                    <p style="color: #7f1d1d; font-size: 14px;">If you didn't request this reset, you can safely ignore this email.</p>
                </div>
            </div>
        `
    }),
    
    welcomeEmail: (userFirstName, companyName) => ({
        subject: 'Welcome to Virajo Studio!',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #ffffff 0%, #fef2f2 100%); border: 2px solid #dc2626; border-radius: 15px; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to Virajo!</h1>
                </div>
                <div style="padding: 40px;">
                    <p style="color: #7f1d1d; font-size: 16px;">Hello ${userFirstName},</p>
                    <p style="color: #7f1d1d; line-height: 1.6;">Welcome to Virajo Studio! Your account for <strong>${companyName}</strong> has been successfully created.</p>
                    <div style="background: rgba(220, 38, 38, 0.05); padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #dc2626;">
                        <h3 style="color: #dc2626; margin-top: 0;">Security Features Enabled:</h3>
                        <ul style="color: #7f1d1d;">
                            <li>Security questions for password recovery</li>
                            <li>Email verification for sensitive actions</li>
                            <li>Advanced template creation tools</li>
                            <li>Social media scheduling</li>
                        </ul>
                    </div>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${process.env.FRONTEND_URL || 'http://localhost:3001'}" style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); color: white; padding: 15px 30px; border-radius: 25px; text-decoration: none; font-weight: bold; display: inline-block;">Start Creating</a>
                    </div>
                </div>
            </div>
        `
    })
};

// Helper function for security questions mapping
function getQuestionText(questionKey) {
    const questions = {
        'pet': 'What was the name of your first pet?',
        'school': 'What elementary school did you attend?',
        'city': 'In what city were you born?',
        'mother': 'What is your mother\'s maiden name?',
        'car': 'What was your first car?',
        'friend': 'What is your best friend\'s name?',
        'street': 'What street did you grow up on?',
        'teacher': 'Who was your favorite teacher?',
        'book': 'What is your favorite book?',
        'movie': 'What is your favorite movie?'
    };
    return questions[questionKey] || questionKey;
}

// ===== Schemas & Models =====
const userSchema = new mongoose.Schema({
    firstName: { type: String },
    lastName: { type: String },
    companyName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String },
    website: { type: String },
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum: ['owner', 'employee', 'admin'], 
        default: 'employee'
    },
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now },
    
    // Security Questions for Password Recovery
    securityQuestions: {
        q1: {
            question: { 
                type: String, 
                enum: ['pet', 'school', 'city', 'mother', 'car', 'friend', 'street', 'teacher', 'book', 'movie']
            },
            answer: { type: String, lowercase: true, trim: true }
        },
        q2: {
            question: { 
                type: String, 
                enum: ['pet', 'school', 'city', 'mother', 'car', 'friend', 'street', 'teacher', 'book', 'movie']
            },
            answer: { type: String, lowercase: true, trim: true }
        }
    },
    
    // Password Reset Tokens
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    tempResetToken: String,
    tempResetExpires: Date,
    
    permissions: {
        canCreatePublicTemplates: { type: Boolean, default: false },
        canManageUsers: { type: Boolean, default: false },
        canViewAnalytics: { type: Boolean, default: false },
        canApproveContent: { type: Boolean, default: false },
        maxPostsPerDay: { type: Number, default: 3 },
        minScheduleHours: { type: Number, default: 24 }
    }
}, { 
    collection: 'users',
    timestamps: true 
});

// Pre-save middleware to set permissions based on role
userSchema.pre('save', function(next) {
    if (this.email) {
        this.email = this.email.toLowerCase();
    }
    
    if (this.isModified('role')) {
        switch(this.role) {
            case 'owner':
                this.permissions = {
                    canCreatePublicTemplates: true,
                    canManageUsers: true,
                    canViewAnalytics: true,
                    canApproveContent: true,
                    maxPostsPerDay: -1,
                    minScheduleHours: 0
                };
                break;
            case 'admin':
                this.permissions = {
                    canCreatePublicTemplates: false,
                    canManageUsers: true,
                    canViewAnalytics: true,
                    canApproveContent: false,
                    maxPostsPerDay: 10,
                    minScheduleHours: 2
                };
                break;
            case 'employee':
            default:
                this.permissions = {
                    canCreatePublicTemplates: false,
                    canManageUsers: false,
                    canViewAnalytics: false,
                    canApproveContent: false,
                    maxPostsPerDay: 3,
                    minScheduleHours: 24
                };
                break;
        }
    }
    next();
});

// Models with fallback support
let User;

try {
    User = mongoose.model('User', userSchema);
    console.log('User model initialized');
} catch (err) {
    console.log('Using fallback storage models');
}

// ===== Helper: JWT Auth =====
function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
        }
        
        try {
            if (global.mongoFallback && !mongoose.connection.readyState) {
                const userData = global.mongoFallback.users.get(decoded.email);
                if (!userData || !userData.isActive) {
                    return res.status(403).json({ status: 'error', message: 'User not found or inactive' });
                }
                req.user = { ...decoded, companyName: userData.companyName };
                next();
            } else {
                const user = await User.findById(decoded.id).select('-password');
                if (!user || !user.isActive) {
                    return res.status(403).json({ status: 'error', message: 'User not found or inactive' });
                }
                req.user = { ...decoded, companyName: user.companyName };
                next();
            }
        } catch (error) {
            return res.status(500).json({ status: 'error', message: 'Authentication error' });
        }
    });
}

// ===== Routes =====

// Health Check
app.get('/health', async (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 
                    global.mongoFallback ? 'fallback-storage' : 'disconnected';
    
    let dbDetails = {};
    
    if (mongoose.connection.readyState === 1) {
        try {
            dbDetails = {
                name: mongoose.connection.db.databaseName,
                host: mongoose.connection.host,
                userCount: await User.countDocuments()
            };
        } catch (e) {}
    }
    
    res.json({ 
        status: 'success', 
        message: 'Virajo Social Studio Server is running',
        timestamp: new Date().toISOString(),
        database: dbStatus,
        details: dbDetails,
        port: PORT,
        email: emailTransporter ? 'configured' : 'not configured'
    });
});

// Registration with Security Questions
app.post('/register', async (req, res) => {
    console.log('Registration attempt:', { 
        email: req.body.email, 
        company: req.body.companyName 
    });
    
    const { 
        firstName, 
        lastName, 
        companyName, 
        email, 
        phone, 
        website, 
        password, 
        role,
        securityQuestions 
    } = req.body;

    try {
        if (!companyName || !email || !password) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Company name, email and password are required' 
            });
        }

        // Validate security questions if provided
        if (securityQuestions) {
            if (!securityQuestions.q1 || !securityQuestions.q1.question || !securityQuestions.q1.answer ||
                !securityQuestions.q2 || !securityQuestions.q2.question || !securityQuestions.q2.answer) {
                return res.status(400).json({ 
                    status: 'error', 
                    message: 'Both security questions and answers are required' 
                });
            }

            if (securityQuestions.q1.question === securityQuestions.q2.question) {
                return res.status(400).json({ 
                    status: 'error', 
                    message: 'Security questions must be different' 
                });
            }
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Check if using fallback storage
        if (global.mongoFallback && !mongoose.connection.readyState) {
            if (global.mongoFallback.users.has(normalizedEmail)) {
                return res.status(400).json({ status: 'error', message: 'User already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const userId = `user_${Date.now()}`;
            
            const newUser = {
                _id: userId,
                firstName: firstName?.trim(),
                lastName: lastName?.trim(),
                companyName: companyName.trim(),
                email: normalizedEmail,
                phone: phone?.trim(),
                website: website?.trim(),
                password: hashedPassword,
                role: role || 'employee',
                isActive: true,
                createdAt: new Date(),
                securityQuestions: securityQuestions ? {
                    q1: {
                        question: securityQuestions.q1.question,
                        answer: securityQuestions.q1.answer.toLowerCase().trim()
                    },
                    q2: {
                        question: securityQuestions.q2.question,
                        answer: securityQuestions.q2.answer.toLowerCase().trim()
                    }
                } : null
            };

            global.mongoFallback.users.set(normalizedEmail, newUser);
            console.log('User saved to fallback storage (temporary)');
            
            const token = jwt.sign(
                { id: userId, email: normalizedEmail, role: newUser.role },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            return res.status(201).json({ 
                status: 'success', 
                message: 'User registered (in temporary storage)',
                token,
                user: {
                    id: userId,
                    firstName: newUser.firstName,
                    lastName: newUser.lastName,
                    email: newUser.email,
                    companyName: newUser.companyName,
                    role: newUser.role,
                    hasSecurityQuestions: !!securityQuestions
                }
            });
        }

        // Normal MongoDB registration
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            console.log('User already exists');
            return res.status(400).json({ status: 'error', message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({
            firstName: firstName?.trim(),
            lastName: lastName?.trim(),
            companyName: companyName.trim(),
            email: normalizedEmail,
            phone: phone?.trim(),
            website: website?.trim(),
            password: hashedPassword,
            role: role || 'employee',
            securityQuestions: securityQuestions ? {
                q1: {
                    question: securityQuestions.q1.question,
                    answer: securityQuestions.q1.answer.toLowerCase().trim()
                },
                q2: {
                    question: securityQuestions.q2.question,
                    answer: securityQuestions.q2.answer.toLowerCase().trim()
                }
            } : undefined
        });

        await newUser.save();
        console.log(`User registered successfully: ${normalizedEmail}`);
        
        const token = jwt.sign(
            { id: newUser._id, email: newUser.email, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send welcome email if configured
        if (emailTransporter) {
            try {
                const welcomeEmail = emailTemplates.welcomeEmail(newUser.firstName, newUser.companyName);
                await emailTransporter.sendMail({
                    from: process.env.EMAIL_FROM || `"Virajo Studio" <${process.env.EMAIL_USER}>`,
                    to: normalizedEmail,
                    ...welcomeEmail
                });
                console.log('Welcome email sent');
            } catch (emailErr) {
                console.log('Welcome email failed:', emailErr.message);
            }
        }

        res.status(201).json({ 
            status: 'success', 
            message: 'User registered successfully',
            token,
            user: {
                id: newUser._id,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                email: newUser.email,
                companyName: newUser.companyName,
                role: newUser.role,
                hasSecurityQuestions: !!newUser.securityQuestions
            }
        });
    } catch (err) {
        console.error('Registration error:', err);
        
        if (err.code === 11000) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email already registered' 
            });
        }
        
        res.status(500).json({ 
            status: 'error', 
            message: 'Registration failed: ' + err.message
        });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', email);

    try {
        if (!email || !password) {
            return res.status(400).json({ status: 'error', message: 'Email and password required' });
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Check if using fallback storage
        if (global.mongoFallback && !mongoose.connection.readyState) {
            const userData = global.mongoFallback.users.get(normalizedEmail);
            if (!userData) {
                console.log('User not found in fallback storage');
                return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
            }

            const validPass = await bcrypt.compare(password, userData.password);
            if (!validPass) {
                return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
            }

            userData.lastLogin = new Date();
            
            const token = jwt.sign(
                { id: userData._id, role: userData.role, email: userData.email, companyName: userData.companyName },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );

            console.log('Login successful (fallback storage)');
            
            return res.json({ 
                status: 'success', 
                token,
                user: {
                    id: userData._id,
                    firstName: userData.firstName,
                    lastName: userData.lastName,
                    email: userData.email,
                    companyName: userData.companyName,
                    role: userData.role,
                    lastLogin: userData.lastLogin
                }
            });
        }

        // Normal MongoDB login
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            console.log('User not found in database');
            return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
        }

        if (!user.isActive) {
            return res.status(400).json({ status: 'error', message: 'Account is deactivated' });
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            console.log('Invalid password');
            return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
        }

        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign(
            { id: user._id, role: user.role, email: user.email, companyName: user.companyName },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log(`Login successful: ${normalizedEmail}`);
        
        res.json({ 
            status: 'success', 
            token,
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                companyName: user.companyName,
                role: user.role,
                permissions: user.permissions,
                lastLogin: user.lastLogin
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ status: 'error', message: 'Login failed: ' + err.message });
    }
});

// Enhanced Forgot Password with Email and Security Questions Support
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    
    try {
        if (!email) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email is required' 
            });
        }

        const normalizedEmail = email.toLowerCase().trim();
        let user;

        if (global.mongoFallback && !mongoose.connection.readyState) {
            user = global.mongoFallback.users.get(normalizedEmail);
        } else {
            user = await User.findOne({ email: normalizedEmail });
        }

        const hasSecurityQuestions = !!(user && user.securityQuestions && 
            user.securityQuestions.q1 && user.securityQuestions.q2);
        
        // Always return success for security
        const standardResponse = {
            status: 'success', 
            message: 'If an account exists with that email, you will receive password reset instructions.',
            hasSecurityQuestions
        };

        if (!user) {
            return res.json(standardResponse);
        }
        
        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        
        if (global.mongoFallback && !mongoose.connection.readyState) {
            user.resetPasswordToken = hashedToken;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
            global.mongoFallback.users.set(normalizedEmail, user);
        } else {
            user.resetPasswordToken = hashedToken;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
            await user.save();
        }

        let emailSent = false;
        
        // Send email if configured
        if (emailTransporter) {
            try {
                const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3001'}/reset-password.html?token=${resetToken}`;
                const emailContent = emailTemplates.passwordReset(resetUrl, user.firstName);
                
                await emailTransporter.sendMail({
                    from: process.env.EMAIL_FROM || `"Virajo Studio" <${process.env.EMAIL_USER}>`,
                    to: normalizedEmail,
                    ...emailContent
                });
                
                console.log('Password reset email sent');
                emailSent = true;
                
            } catch (emailErr) {
                console.log('Email sending failed:', emailErr.message);
            }
        }
        
        standardResponse.emailSent = emailSent;
        res.json(standardResponse);
        
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to process password reset request' 
        });
    }
});

// Get Security Questions
app.post('/get-security-questions', async (req, res) => {
    const { email } = req.body;

    try {
        if (!email) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email is required' 
            });
        }

        const normalizedEmail = email.toLowerCase().trim();
        let user;

        if (global.mongoFallback && !mongoose.connection.readyState) {
            user = global.mongoFallback.users.get(normalizedEmail);
        } else {
            user = await User.findOne({ email: normalizedEmail });
        }
        
        if (!user || !user.securityQuestions) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email not found or security questions not set up' 
            });
        }

        const questions = [
            getQuestionText(user.securityQuestions.q1.question),
            getQuestionText(user.securityQuestions.q2.question)
        ];

        res.json({ 
            status: 'success', 
            questions 
        });

    } catch (err) {
        console.error('Get security questions error:', err);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to retrieve security questions' 
        });
    }
});

// Verify Security Questions
app.post('/verify-security-questions', async (req, res) => {
    const { email, answers } = req.body;

    try {
        if (!email || !answers || answers.length !== 2) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email and both security answers are required' 
            });
        }

        const normalizedEmail = email.toLowerCase().trim();
        let user;

        if (global.mongoFallback && !mongoose.connection.readyState) {
            user = global.mongoFallback.users.get(normalizedEmail);
        } else {
            user = await User.findOne({ email: normalizedEmail });
        }
        
        if (!user || !user.securityQuestions) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Security questions not found' 
            });
        }

        const answer1Match = user.securityQuestions.q1.answer === answers[0].toLowerCase().trim();
        const answer2Match = user.securityQuestions.q2.answer === answers[1].toLowerCase().trim();

        if (!answer1Match || !answer2Match) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Incorrect answers to security questions' 
            });
        }

        // Generate temporary reset token
        const tempToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(tempToken).digest('hex');
        
        if (global.mongoFallback && !mongoose.connection.readyState) {
            user.tempResetToken = hashedToken;
            user.tempResetExpires = Date.now() + 1800000; // 30 minutes
            global.mongoFallback.users.set(normalizedEmail, user);
        } else {
            user.tempResetToken = hashedToken;
            user.tempResetExpires = Date.now() + 1800000; // 30 minutes
            await user.save();
        }

        console.log('Security questions verified successfully');

        res.json({ 
            status: 'success', 
            message: 'Security questions verified',
            tempToken: tempToken 
        });

    } catch (err) {
        console.error('Verify security questions error:', err);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to verify security questions' 
        });
    }
});

// Reset Password (Enhanced with dual token support)
app.post('/reset-password', async (req, res) => {
    const { token, tempToken, newPassword, email } = req.body;
    
    try {
        if ((!token && !tempToken) || !newPassword) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Reset token and new password are required' 
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Password must be at least 8 characters long' 
            });
        }

        let user;
        
        if (global.mongoFallback && !mongoose.connection.readyState) {
            const normalizedEmail = email?.toLowerCase().trim();
            if (normalizedEmail) {
                user = global.mongoFallback.users.get(normalizedEmail);
                if (user) {
                    const tokenField = token ? 'resetPasswordToken' : 'tempResetToken';
                    const expiresField = token ? 'resetPasswordExpires' : 'tempResetExpires';
                    const hashedToken = crypto.createHash('sha256').update(token || tempToken).digest('hex');
                    
                    if (user[tokenField] !== hashedToken || 
                        !user[expiresField] || 
                        Date.now() > user[expiresField]) {
                        user = null;
                    }
                }
            }
        } else {
            if (token) {
                const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
                user = await User.findOne({
                    resetPasswordToken: hashedToken,
                    resetPasswordExpires: { $gt: Date.now() }
                });
            } else if (tempToken) {
                const hashedTempToken = crypto.createHash('sha256').update(tempToken).digest('hex');
                user = await User.findOne({
                    tempResetToken: hashedTempToken,
                    tempResetExpires: { $gt: Date.now() }
                });
            }
        }
        
        if (!user) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Invalid or expired reset token' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        if (global.mongoFallback && !mongoose.connection.readyState) {
            user.password = hashedPassword;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            user.tempResetToken = undefined;
            user.tempResetExpires = undefined;
            global.mongoFallback.users.set(user.email, user);
        } else {
            user.password = hashedPassword;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            user.tempResetToken = undefined;
            user.tempResetExpires = undefined;
            await user.save();
        }
        
        console.log('Password reset successful for:', user.email);
        
        res.json({ 
            status: 'success', 
            message: 'Password reset successful!' 
        });
        
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to reset password' 
        });
    }
});

// Get User Profile
app.get('/profile', authenticate, async (req, res) => {
    try {
        if (global.mongoFallback && !mongoose.connection.readyState) {
            const userData = global.mongoFallback.users.get(req.user.email);
            return res.json({ status: 'success', user: userData });
        }

        const user = await User.findById(req.user.id).select('-password');
        res.json({ status: 'success', user });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Serve Frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log('\n================================');
    console.log('🚀 Virajo Social Studio Server');
    console.log('================================');
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`🔐 JWT: ${process.env.JWT_SECRET ? '✅ Set' : '❌ Not Set'}`);
    console.log(`💾 MongoDB: ${process.env.MONGO_URI ? '✅ Configured' : '❌ Not Set'}`);
    console.log(`📧 Email: ${emailTransporter ? '✅ Configured' : '❌ Not Set'}`);
    console.log('================================');
    console.log('📋 API Endpoints:');
    console.log('   POST /register                     - User registration');
    console.log('   POST /login                        - User authentication');
    console.log('   POST /forgot-password              - Initialize password reset');
    console.log('   POST /get-security-questions       - Get security questions');
    console.log('   POST /verify-security-questions    - Verify security answers');
    console.log('   POST /reset-password               - Reset password');
    console.log('   GET  /profile                      - Get user profile');
    console.log('   GET  /health                       - Server health check');
    console.log('================================');
    console.log('🎯 Server ready for connections\n');
});