const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const MetaApi = require('metaapi.cloud-sdk');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-exness-secret-key-2024';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const METAAPI_TOKEN = process.env.METAAPI_TOKEN || 'your-metaapi-token-here';

// ==================== DATA SETUP ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            metaapiAccountId: "",
            exnessLogin: "",
            exnessServer: "",
            lastBalance: 0,
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== METAAPI CLOUD INITIALIZATION ====================
let api = null;
let activeConnections = new Map();

try {
    if (METAAPI_TOKEN && METAAPI_TOKEN !== 'your-metaapi-token-here') {
        api = new MetaApi(METAAPI_TOKEN);
        console.log('✅ MetaApi Cloud initialized');
    } else {
        console.log('⚠️ METAAPI_TOKEN not set. Please add your MetaApi token to environment variables.');
        console.log('   Get your free token at https://metaapi.cloud');
    }
} catch (error) {
    console.error('❌ MetaApi initialization error:', error.message);
}

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User exists' });
    
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Request sent to owner' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = { 
        email, 
        password: pending[email].password, 
        isOwner: false, 
        isApproved: true, 
        isBlocked: false, 
        metaapiAccountId: "",
        exnessLogin: "",
        exnessServer: "",
        lastBalance: 0,
        createdAt: pending[email].requestedAt 
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Approved ${email}` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Rejected ${email}` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({ 
        email, 
        hasExnessCreds: !!users[email].exnessLogin, 
        isOwner: users[email].isOwner, 
        isApproved: users[email].isApproved, 
        isBlocked: users[email].isBlocked,
        balance: users[email].lastBalance || 0
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.metaapiAccountId) {
            balances[email] = { balance: 0, hasConnection: false };
            continue;
        }
        
        try {
            const account = await api.metatraderAccountApi.getAccount(userData.metaapiAccountId);
            const accountInfo = await account.getAccountInformation();
            balances[email] = { 
                balance: accountInfo.balance, 
                hasConnection: true,
                lastUpdated: new Date().toISOString()
            };
            userData.lastBalance = accountInfo.balance;
            writeUsers(users);
        } catch (error) {
            balances[email] = { balance: userData.lastBalance || 0, hasConnection: false, error: error.message };
        }
    }
    
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    
    res.json({ success: true, trades: allTrades });
});

// ==================== EXNESS ACCOUNT ROUTES (via MetaApi) ====================
app.post('/api/set-exness-creds', authenticate, async (req, res) => {
    try {
        const { exnessLogin, exnessPassword, exnessServer } = req.body;
        if (!exnessLogin || !exnessPassword || !exnessServer) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }
        
        if (!api) {
            return res.status(500).json({ success: false, message: 'MetaApi not configured. Please add METAAPI_TOKEN to environment variables.' });
        }
        
        // Create MetaApi account
        const account = await api.metatraderAccountApi.createAccount({
            type: 'cloud',
            platform: 'mt5',
            login: parseInt(exnessLogin),
            password: exnessPassword,
            server: exnessServer,
            description: `Halal Trading Bot - ${req.user.email}`
        });
        
        // Deploy to cloud
        await account.deploy();
        
        // Get account info
        const accountInfo = await account.getAccountInformation();
        
        // Save to user
        const users = readUsers();
        users[req.user.email].metaapiAccountId = account.id;
        users[req.user.email].exnessLogin = encrypt(exnessLogin);
        users[req.user.email].exnessServer = encrypt(exnessServer);
        users[req.user.email].lastBalance = accountInfo.balance;
        writeUsers(users);
        
        res.json({ success: true, message: `Connected! Balance: $${accountInfo.balance.toFixed(2)}`, balance: accountInfo.balance });
    } catch (error) {
        console.error('Exness connection error:', error);
        res.status(401).json({ success: false, message: error.message });
    }
});

app.post('/api/connect-exness', authenticate, async (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.metaapiAccountId) {
            return res.status(400).json({ success: false, message: 'No Exness credentials saved.' });
        }
        
        const account = await api.metatraderAccountApi.getAccount(user.metaapiAccountId);
        const accountInfo = await account.getAccountInformation();
        
        user.lastBalance = accountInfo.balance;
        writeUsers(users);
        
        res.json({ success: true, balance: accountInfo.balance, totalBalance: accountInfo.balance, message: `Connected! Balance: $${accountInfo.balance.toFixed(2)}` });
    } catch (error) {
        console.error('Connection error:', error);
        res.status(401).json({ success: false, message: error.message });
    }
});

app.get('/api/get-exness-creds', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.exnessLogin) return res.json({ success: false });
    res.json({ 
        success: true, 
        exnessLogin: decrypt(user.exnessLogin),
        exnessServer: decrypt(user.exnessServer)
    });
});

// ==================== AI SIGNAL GENERATION ====================
function calculateRSI(prices, period = 14) {
    if (prices.length < period + 1) return 50;
    let gains = 0, losses = 0;
    for (let i = prices.length - period; i < prices.length; i++) {
        const change = prices[i] - prices[i - 1];
        if (change >= 0) gains += change;
        else losses -= change;
    }
    const avgGain = gains / period;
    const avgLoss = losses / period;
    if (avgLoss === 0) return 100;
    const rs = avgGain / avgLoss;
    return 100 - (100 / (1 + rs));
}

async function getAISignal(symbol, account) {
    try {
        // Get historical rates
        const rates = await account.getRates(symbol, 'M5', 100);
        const prices = rates.map(r => r.close);
        const currentPrice = prices[prices.length - 1];
        
        // Calculate indicators
        const rsi = calculateRSI(prices);
        const ma20 = prices.slice(-20).reduce((a, b) => a + b, 0) / 20;
        const ma50 = prices.slice(-50).reduce((a, b) => a + b, 0) / 50;
        const momentum = ((prices[prices.length - 1] - prices[prices.length - 5]) / prices[prices.length - 5]) * 100;
        
        let action = 'HOLD';
        let confidence = 0;
        let reasons = [];
        
        // Buy signals
        if (rsi < 30) {
            action = 'BUY';
            confidence = 0.85;
            reasons.push(`RSI oversold (${rsi.toFixed(1)})`);
        } else if (rsi < 40 && ma20 > ma50) {
            action = 'BUY';
            confidence = 0.75;
            reasons.push(`RSI ${rsi.toFixed(1)} in buy zone, uptrend`);
        } else if (momentum > 0.2 && ma20 > ma50) {
            action = 'BUY';
            confidence = 0.7;
            reasons.push(`Positive momentum ${momentum.toFixed(2)}%`);
        }
        
        // Sell signals
        if (rsi > 70) {
            action = 'SELL';
            confidence = 0.85;
            reasons.push(`RSI overbought (${rsi.toFixed(1)})`);
        } else if (rsi > 60 && ma20 < ma50) {
            action = 'SELL';
            confidence = 0.75;
            reasons.push(`RSI ${rsi.toFixed(1)} in sell zone, downtrend`);
        } else if (momentum < -0.2 && ma20 < ma50) {
            action = 'SELL';
            confidence = 0.7;
            reasons.push(`Negative momentum ${momentum.toFixed(2)}%`);
        }
        
        console.log(`🤖 AI [${symbol}]: ${action} (${(confidence*100).toFixed(0)}%) | RSI:${rsi.toFixed(1)} | ${reasons.join(', ')}`);
        
        return { action, confidence, reasons, currentPrice };
    } catch (error) {
        console.error('AI error:', error.message);
        return { action: 'HOLD', confidence: 0, reasons: ['Error'], currentPrice: 0 };
    }
}

async function shouldClosePosition(position, currentPrice, account) {
    const profitPercent = ((currentPrice - position.entryPrice) / position.entryPrice) * 100 * (position.side === 'buy' ? 1 : -1);
    
    // Get current market conditions
    const rates = await account.getRates(position.symbol, 'M1', 20);
    const prices = rates.map(r => r.close);
    const rsi = calculateRSI(prices);
    const momentum = ((prices[prices.length - 1] - prices[prices.length - 3]) / prices[prices.length - 3]) * 100;
    
    let shouldClose = false;
    let reason = '';
    
    if (profitPercent > 0) {
        // Dynamic profit taking based on market strength
        if (profitPercent >= 3) {
            shouldClose = true;
            reason = `High profit ${profitPercent.toFixed(2)}%`;
        } else if (profitPercent >= 1.5) {
            if ((position.side === 'buy' && rsi > 70) || (position.side === 'sell' && rsi < 30)) {
                shouldClose = true;
                reason = `Profit ${profitPercent.toFixed(2)}% with reversal signal`;
            } else if ((position.side === 'buy' && momentum < 0) || (position.side === 'sell' && momentum > 0)) {
                shouldClose = true;
                reason = `Profit ${profitPercent.toFixed(2)}% with weakening momentum`;
            }
        }
    } else if (profitPercent < 0) {
        if (profitPercent <= -2) {
            shouldClose = true;
            reason = `Stop loss ${Math.abs(profitPercent).toFixed(2)}%`;
        }
    }
    
    if (shouldClose) {
        console.log(`🎯 CLOSE ${position.symbol}: ${reason}`);
    }
    
    return { shouldClose, reason, profitPercent };
}

// ==================== TRADING ENGINE ====================
const activeSessions = {};

class HalalTradingEngine {
    constructor(sessionId, userEmail, config, account) {
        this.sessionId = sessionId;
        this.userEmail = userEmail;
        this.config = config;
        this.account = account;
        this.isActive = true;
        this.currentProfit = 0;
        this.trades = [];
        this.winStreak = 0;
        this.analysisInterval = null;
        this.monitorInterval = null;
        this.startTime = Date.now();
        this.openPositions = [];
    }
    
    async start() {
        console.log(`🕋 Starting Halal trading engine for ${this.userEmail}`);
        
        // Connect to account
        await this.account.connect();
        
        // Analysis every 10 seconds
        this.analysisInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
            if (elapsedHours >= this.config.timeLimit) {
                await this.stop();
                return;
            }
            
            if (this.currentProfit >= this.config.targetProfit) {
                console.log(`🎯 Target reached! Total profit: $${this.currentProfit.toFixed(2)}`);
                await this.stop();
                return;
            }
            
            for (const symbol of this.config.tradingPairs) {
                if (!this.isActive) break;
                
                const hasPosition = this.openPositions.some(p => p.symbol === symbol);
                
                if (!hasPosition) {
                    const signal = await getAISignal(symbol, this.account);
                    
                    if (signal.action === 'BUY' && signal.confidence >= 0.7) {
                        await this.executeTrade(symbol, 'buy', signal);
                    } else if (signal.action === 'SELL' && signal.confidence >= 0.7) {
                        await this.executeTrade(symbol, 'sell', signal);
                    }
                }
            }
        }, 10000);
        
        // Monitor positions every 2 seconds
        this.monitorInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            for (const position of this.openPositions) {
                try {
                    const price = await this.account.getSymbolPrice(position.symbol);
                    const currentPrice = position.side === 'buy' ? price.bid : price.ask;
                    const closeDecision = await shouldClosePosition(position, currentPrice, this.account);
                    
                    if (closeDecision.shouldClose) {
                        await this.closePosition(position, closeDecision.profitPercent);
                    } else {
                        // Update unrealized profit for display
                        const unrealizedProfit = ((currentPrice - position.entryPrice) / position.entryPrice) * 100 * (position.side === 'buy' ? 1 : -1);
                        position.unrealizedProfit = unrealizedProfit;
                    }
                } catch (error) {
                    console.error(`Monitor error:`, error.message);
                }
            }
        }, 2000);
    }
    
    async executeTrade(symbol, side, signal) {
        if (this.openPositions.some(p => p.symbol === symbol)) return;
        
        try {
            const accountInfo = await this.account.getAccountInformation();
            let volume = this.config.investmentAmount / 100000;
            if (volume < 0.01) volume = 0.01;
            if (volume > 1.0) volume = 1.0;
            
            if (accountInfo.balance < this.config.investmentAmount + 50) {
                console.log(`⚠️ Insufficient balance: $${accountInfo.balance.toFixed(2)}`);
                return;
            }
            
            const price = await this.account.getSymbolPrice(symbol);
            const entryPrice = side === 'buy' ? price.ask : price.bid;
            
            console.log(`📈 Opening ${side.toUpperCase()} for ${symbol} with ${volume} lots`);
            
            let order;
            if (side === 'buy') {
                order = await this.account.createMarketBuyOrder(symbol, volume);
            } else {
                order = await this.account.createMarketSellOrder(symbol, volume);
            }
            
            this.openPositions.push({
                symbol: symbol,
                side: side,
                volume: volume,
                entryPrice: entryPrice,
                orderId: order.id,
                openedAt: Date.now(),
                aiConfidence: signal.confidence,
                aiReason: signal.reasons[0]
            });
            
            this.trades.unshift({
                symbol: symbol,
                side: `${side.toUpperCase()} OPEN`,
                entryPrice: entryPrice.toFixed(5),
                volume: volume,
                aiConfidence: `${(signal.confidence * 100).toFixed(0)}%`,
                timestamp: new Date().toISOString()
            });
            
            console.log(`✅ ${side.toUpperCase()} opened for ${symbol} at $${entryPrice.toFixed(5)}`);
        } catch (error) {
            console.error(`Trade execution error:`, error.message);
        }
    }
    
    async closePosition(position, profitPercent) {
        try {
            await this.account.closeOrder(position.orderId);
            
            const profit = (profitPercent / 100) * (position.volume * 100000 * position.entryPrice);
            this.currentProfit += profit;
            this.winStreak = profit > 0 ? this.winStreak + 1 : 0;
            
            this.trades.unshift({
                symbol: position.symbol,
                side: `${position.side.toUpperCase()} CLOSED`,
                entryPrice: position.entryPrice.toFixed(5),
                profit: profit.toFixed(2),
                profitPercent: profitPercent.toFixed(2),
                timestamp: new Date().toISOString()
            });
            
            // Save to file
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                profit: profit,
                profitPercent: profitPercent,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            // Remove from open positions
            this.openPositions = this.openPositions.filter(p => p.orderId !== position.orderId);
            
            const profitSymbol = profit >= 0 ? '+' : '';
            console.log(`✅ CLOSED ${position.symbol} | Profit: ${profitSymbol}$${profit.toFixed(2)} (${profitPercent.toFixed(2)}%) | Total: $${this.currentProfit.toFixed(2)}`);
        } catch (error) {
            console.error(`Close error:`, error.message);
        }
    }
    
    async stop() {
        console.log(`🛑 Stopping Halal trading engine for ${this.userEmail}`);
        this.isActive = false;
        
        if (this.analysisInterval) clearInterval(this.analysisInterval);
        if (this.monitorInterval) clearInterval(this.monitorInterval);
        
        // Close all open positions
        for (const position of this.openPositions) {
            try {
                const price = await this.account.getSymbolPrice(position.symbol);
                const currentPrice = position.side === 'buy' ? price.bid : price.ask;
                const profitPercent = ((currentPrice - position.entryPrice) / position.entryPrice) * 100 * (position.side === 'buy' ? 1 : -1);
                await this.closePosition(position, profitPercent);
            } catch (error) {
                console.error(`Stop close error:`, error.message);
            }
        }
        
        // Disconnect account
        await this.account.disconnect();
    }
    
    getStatus() {
        const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, this.config.timeLimit - elapsedHours);
        const progressPercent = this.config.targetProfit > 0 ? (this.currentProfit / this.config.targetProfit) * 100 : 0;
        
        return {
            isActive: this.isActive,
            currentProfit: this.currentProfit,
            targetProfit: this.config.targetProfit,
            winStreak: this.winStreak,
            timeRemaining: timeRemaining,
            progressPercent: progressPercent,
            openPositions: this.openPositions.length,
            trades: this.trades.slice(0, 30)
        };
    }
}

const engines = {};

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetProfit, timeLimit, tradingPairs } = req.body;
        
        if (investmentAmount < 3) return res.status(400).json({ success: false, message: 'Minimum investment is $3' });
        if (targetProfit < 1) return res.status(400).json({ success: false, message: 'Target profit must be at least $1' });
        if (!timeLimit || timeLimit < 0.1) return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });

        if (!api) {
            return res.status(500).json({ success: false, message: 'MetaApi not configured. Please add METAAPI_TOKEN to environment variables.' });
        }

        const users = readUsers();
        const user = users[req.user.email];
        if (!user.metaapiAccountId) return res.status(400).json({ success: false, message: 'Please add Exness credentials first' });

        const account = await api.metatraderAccountApi.getAccount(user.metaapiAccountId);
        const accountInfo = await account.getAccountInformation();
        
        if (!accountInfo || accountInfo.balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have $${accountInfo?.balance?.toFixed(2) || 0} USD, need $${investmentAmount}` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        
        const config = {
            investmentAmount: investmentAmount,
            targetProfit: targetProfit,
            timeLimit: timeLimit,
            tradingPairs: tradingPairs || ['XAUUSD', 'EURUSD', 'GBPUSD']
        };
        
        const engine = new HalalTradingEngine(sessionId, req.user.email, config, account);
        engines[sessionId] = engine;
        await engine.start();
        
        res.json({ 
            success: true, 
            sessionId, 
            message: `✅ HALAL TRADING STARTED! AI analyzes continuously and closes positions at maximum profit.` 
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (engines[sessionId]) {
        engines[sessionId].stop();
        delete engines[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const engine = engines[sessionId];
    if (!engine) return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
    
    const status = engine.getStatus();
    res.json({
        success: true,
        currentProfit: status.currentProfit,
        targetProfit: status.targetProfit,
        newTrades: status.trades,
        winStreak: status.winStreak,
        timeRemaining: status.timeRemaining,
        progressPercent: status.progressPercent,
        openPositions: status.openPositions,
        isActive: status.isActive
    });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL EXNESS TRADING BOT - MetaApi Cloud Edition`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Login: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Minimum Investment: $3`);
    console.log(`✅ NO FIXED TAKE PROFIT - AI decides when to close`);
    console.log(`✅ AI analyzes continuously | Unlimited concurrent trades`);
    console.log(`✅ 100% Halal - No Riba, No Gharar, No Maysir\n`);
});
