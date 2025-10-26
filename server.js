// ============================================
// SERVER.JS - Backend Seguro Portal Freguesia (corrigido)
// ============================================

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const morgan = require('morgan');
const winston = require('winston');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();

// ============================================
// 1. SEGURANÇA & PARSERS
// ============================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// CORS dinâmico para múltiplas origens
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

console.log('🔐 CORS - Origens permitidas:', allowedOrigins);

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // Postman/curl
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return cb(null, true);
    console.log('❌ CORS bloqueou origem:', origin);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400
};
app.use(cors(corsOptions));
// garante resposta ao preflight
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

// ============================================
// 2. RATE LIMITING
// ============================================

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Demasiados pedidos deste IP, tente novamente mais tarde.',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiadas tentativas de login. Conta temporariamente bloqueada.',
  skipSuccessfulRequests: true,
});

const incidentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Limite de incidências atingido. Tente novamente mais tarde.',
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ============================================
// 3. LOGGING
// ============================================

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));

// ============================================
// 4. MODELOS (Mongoose)
// ============================================

const userSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Nome é obrigatório'], trim: true, maxlength: [100, 'Nome muito longo'] },
  email: {
    type: String, required: [true, 'Email é obrigatório'], unique: true, lowercase: true, trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Email inválido']
  },
  phone: {
    type: String, trim: true,
    match: [/^\+?[0-9\s\-()]+$/, 'Telefone inválido'] // ← regex completa (corrigida)
  },
  password: { type: String, required: [true, 'Password é obrigatória'], minlength: [8, 'Password deve ter no mínimo 8 caracteres'], select: false },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationTokenExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  consentGiven: { type: Boolean, required: true, default: false }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.comparePassword = async function(candidate) { return bcrypt.compare(candidate, this.password); };
userSchema.methods.isLocked = function() { return !!(this.lockUntil && this.lockUntil > Date.now()); };

const User = mongoose.model('User', userSchema);

const incidentSchema = new mongoose.Schema({
  title: { type: String, required: [true, 'Título é obrigatório'], trim: true, maxlength: [200, 'Título muito longo'] },
  description: { type: String, required: [true, 'Descrição é obrigatória'], trim: true, maxlength: [2000, 'Descrição muito longa'] },
  location: { type: String, required: [true, 'Localização é obrigatória'], trim: true, maxlength: [300, 'Localização muito longa'] },
  gps: {
    type: String, trim: true,
    match: [/^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$/, 'Coordenadas GPS inválidas']
  },
  status: { type: String, enum: ['pending', 'analyzing', 'inProgress', 'resolved', 'rejected'], default: 'pending' },
  photos: [{ type: String, maxlength: [500, 'URL da foto muito longo'] }],
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  moderatorNotes: { type: String, maxlength: [1000, 'Notas muito longas'] },
  resolvedDate: Date,
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });
incidentSchema.index({ status: 1, createdAt: -1 });
incidentSchema.index({ user: 1 });
const Incident = mongoose.model('Incident', incidentSchema);

const newsSchema = new mongoose.Schema({
  title: { type: String, required: [true, 'Título é obrigatório'], trim: true, maxlength: [200, 'Título muito longo'] },
  excerpt: { type: String, required: [true, 'Resumo é obrigatório'], trim: true, maxlength: [500, 'Resumo muito longo'] },
  content: { type: String, required: [true, 'Conteúdo é obrigatório'], maxlength: [10000, 'Conteúdo muito longo'] },
  image: { type: String, required: [true, 'Imagem é obrigatória'] },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  published: { type: Boolean, default: false },
  publishDate: Date
}, { timestamps: true });
const News = mongoose.model('News', newsSchema);

const slideSchema = new mongoose.Schema({
  title: { type: String, required: [true, 'Título é obrigatório'], trim: true, maxlength: [100, 'Título muito longo'] },
  image: { type: String, required: [true, 'Imagem é obrigatória'] },
  order: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
}, { timestamps: true });
const Slide = mongoose.model('Slide', slideSchema);

const linkSchema = new mongoose.Schema({
  title: { type: String, required: [true, 'Título é obrigatório'], trim: true, maxlength: [100, 'Título muito longo'] },
  url: { type: String, required: [true, 'URL é obrigatória'], trim: true, match: [/^https?:\/\/.+/, 'URL inválida'] },
  order: { type: Number, default: 0 },
  active: { type: Boolean, default: true }
}, { timestamps: true });
const Link = mongoose.model('Link', linkSchema);

const auditSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true, enum: ['login','logout','register','password_change','incident_create','incident_update','incident_delete','user_update','user_delete','news_create','news_update','news_delete'] },
  resource: { type: String, required: true },
  resourceId: mongoose.Schema.Types.ObjectId,
  ipAddress: String,
  userAgent: String,
  details: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});
auditSchema.index({ user: 1, timestamp: -1 });
auditSchema.index({ action: 1, timestamp: -1 });
const AuditLog = mongoose.model('AuditLog', auditSchema);

// ============================================
// 5. AUTH
// ============================================

const generateToken = (userId) => jwt.sign(
  { id: userId },
  process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
  { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
);

const authenticate = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) return res.status(401).json({ success: false, message: 'Não autenticado. Token em falta.' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production');
    const user = await User.findById(decoded.id).select('-password');
    if (!user) return res.status(401).json({ success: false, message: 'Utilizador não encontrado.' });
    if (!user.isVerified) return res.status(403).json({ success: false, message: 'Email não verificado. Verifique o seu email.' });

    req.user = user;
    next();
  } catch (error) {
    logger.error({ msg: 'Authentication error', error });
    return res.status(401).json({ success: false, message: 'Token inválido ou expirado.' });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'Não tem permissão para aceder a este recurso.' });
  }
  next();
};

// Auditoria
const auditLog = (action, resource) => async (req, res, next) => {
  try {
    await AuditLog.create({
      user: req.user ? req.user._id : null,
      action, resource,
      resourceId: req.params.id || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { body: req.body, params: req.params },
      timestamp: new Date()
    });
  } catch (error) {
    logger.error({ msg: 'Audit log error', error });
  }
  next();
};

// ============================================
// 6. VALIDAÇÕES
// ============================================

const validateRegistration = [
  body('name').trim().notEmpty().withMessage('Nome é obrigatório')
    .isLength({ min: 2, max: 100 }).withMessage('Nome deve ter entre 2 e 100 caracteres')
    .matches(/^[a-zA-ZÀ-ÿ\s]+$/).withMessage('Nome deve conter apenas letras'),
  body('email').trim().normalizeEmail().isEmail().withMessage('Email inválido').isLength({ max: 100 }).withMessage('Email muito longo'),
  body('phone').optional().trim().matches(/^\+?[0-9\s\-()]+$/).withMessage('Telefone inválido'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password deve ter no mínimo 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password deve conter maiúsculas, minúsculas, números e símbolos'),
  body('consentGiven').isBoolean().withMessage('consentGiven inválido')
];

const validateLogin = [
  body('email').trim().normalizeEmail().isEmail().withMessage('Email inválido'),
  body('password').notEmpty().withMessage('Password é obrigatória')
];

const validateIncident = [
  body('title').trim().notEmpty().withMessage('Título é obrigatório').isLength({ min: 5, max: 200 }).withMessage('Título deve ter entre 5 e 200 caracteres'),
  body('description').trim().notEmpty().withMessage('Descrição é obrigatória').isLength({ min: 10, max: 2000 }).withMessage('Descrição deve ter entre 10 e 2000 caracteres'),
  body('location').trim().notEmpty().withMessage('Localização é obrigatória').isLength({ max: 300 }).withMessage('Localização muito longa'),
  body('gps').optional().trim()
    .matches(/^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$/)
    .withMessage('Coordenadas GPS inválidas')
];

// ============================================
// 7. HEALTHCHECK
// ============================================

app.get('/health', (_req, res) => res.status(200).json({ success: true, message: 'API is running', timestamp: new Date().toISOString() }));
app.get('/api/health', (_req, res) => res.status(200).json({ success: true, message: 'API is running', timestamp: new Date().toISOString() })); // alinhado com docs  [oai_citation:3‡Documento 1 - Esta é uma cópia de um chat entre Claude e Marco .pdf](sediment://file_00000000ee2861f59306f6758d8a4ce6)
app.get('/', (_req, res) => res.status(200).json({ success: true, message: 'Portal Freguesia API - Running' }));

// ============================================
// 8. AUTENTICAÇÃO
// ============================================

app.post('/api/auth/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

    const { name, email, phone, password, consentGiven } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: 'Email já registado.' });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;

    const user = await User.create({ name, email, phone, password, consentGiven, verificationToken, verificationTokenExpires });

    logger.info({ msg: 'New user registered', email });
    await AuditLog.create({ user: user._id, action: 'register', resource: 'User', resourceId: user._id, ipAddress: req.ip, userAgent: req.get('user-agent') });

    res.status(201).json({ success: true, message: 'Conta criada com sucesso! Verifique o seu email para ativar a conta.', data: { userId: user._id, email: user.email } });
  } catch (error) {
    logger.error({ msg: 'Registration error', error });
    res.status(500).json({ success: false, message: 'Erro ao criar conta. Tente novamente.' });
  }
});

app.post('/api/auth/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user) return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });

    if (user.isLocked()) return res.status(423).json({ success: false, message: 'Conta temporariamente bloqueada devido a múltiplas tentativas falhadas.' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) { user.lockUntil = Date.now() + 30 * 60 * 1000; logger.warn({ msg: 'Account locked due to failed attempts', email }); }
      await user.save();
      return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
    }

    user.loginAttempts = 0; user.lockUntil = undefined; user.lastLogin = Date.now(); await user.save();
    const token = generateToken(user._id);

    logger.info({ msg: 'User logged in', email });
    await AuditLog.create({ user: user._id, action: 'login', resource: 'User', resourceId: user._id, ipAddress: req.ip, userAgent: req.get('user-agent') });

    res.json({ success: true, message: 'Login efetuado com sucesso!', data: { token, user: { id: user._id, name: user.name, email: user.email, role: user.role, isVerified: user.isVerified } } });
  } catch (error) {
    logger.error({ msg: 'Login error', error });
    res.status(500).json({ success: false, message: 'Erro ao efetuar login. Tente novamente.' });
  }
});

app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token, verificationTokenExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ success: false, message: 'Token inválido ou expirado.' });
    user.isVerified = true; user.verificationToken = undefined; user.verificationTokenExpires = undefined; await user.save();
    logger.info({ msg: 'Email verified', email: user.email });
    res.json({ success: true, message: 'Email verificado com sucesso! Pode agora fazer login.' });
  } catch (error) {
    logger.error({ msg: 'Email verification error', error });
    res.status(500).json({ success: false, message: 'Erro ao verificar email.' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({ success: true, data: { user: req.user } });
});

// ============================================
// 9. INCIDÊNCIAS
// ============================================

app.post('/api/incidents', authenticate, incidentLimiter, validateIncident, auditLog('incident_create', 'Incident'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

    const { title, description, location, gps, photos } = req.body;
    const incident = await Incident.create({ title, description, location, gps, photos: photos || [], user: req.user._id, status: 'pending' });

    logger.info({ msg: 'Incident created', user: req.user.email, incidentId: incident._id });
    res.status(201).json({ success: true, message: 'Incidência reportada com sucesso!', data: { incident } });
  } catch (error) {
    logger.error({ msg: 'Create incident error', error });
    res.status(500).json({ success: false, message: 'Erro ao reportar incidência.' });
  }
});

app.get('/api/incidents/public', async (_req, res) => {
  try {
    const incidents = await Incident.find({ status: { $in: ['pending', 'analyzing', 'inProgress', 'resolved'] } })
      .select('-user -moderatorNotes -__v').sort('-createdAt').limit(100);
    res.json({ success: true, count: incidents.length, data: { incidents } });
  } catch (error) {
    logger.error({ msg: 'List incidents error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar incidências.' });
  }
});

app.get('/api/incidents/my', authenticate, async (req, res) => {
  try {
    const incidents = await Incident.find({ user: req.user._id }).sort('-createdAt');
    res.json({ success: true, count: incidents.length, data: { incidents } });
  } catch (error) {
    logger.error({ msg: 'List my incidents error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar incidências.' });
  }
});

app.get('/api/incidents/:id', async (req, res) => {
  try {
    const incident = await Incident.findById(req.params.id).select('-user -moderatorNotes -__v');
    if (!incident) return res.status(404).json({ success: false, message: 'Incidência não encontrada.' });
    res.json({ success: true, data: { incident } });
  } catch (error) {
    logger.error({ msg: 'Get incident error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar incidência.' });
  }
});

app.patch('/api/incidents/:id/status', authenticate, authorize('moderator', 'admin'), auditLog('incident_update', 'Incident'), async (req, res) => {
  try {
    const { status, moderatorNotes } = req.body;
    if (!['pending', 'analyzing', 'inProgress', 'resolved', 'rejected'].includes(status)) return res.status(400).json({ success: false, message: 'Estado inválido.' });

    const incident = await Incident.findById(req.params.id).populate('user', 'email name');
    if (!incident) return res.status(404).json({ success: false, message: 'Incidência não encontrada.' });

    incident.status = status;
    if (moderatorNotes) incident.moderatorNotes = moderatorNotes;
    if (status === 'resolved') incident.resolvedDate = Date.now();
    await incident.save();

    logger.info({ msg: 'Incident status updated', incidentId: incident._id, status, by: req.user.email });
    res.json({ success: true, message: 'Estado atualizado com sucesso!', data: { incident } });
  } catch (error) {
    logger.error({ msg: 'Update incident error', error });
    res.status(500).json({ success: false, message: 'Erro ao atualizar incidência.' });
  }
});

app.delete('/api/incidents/:id', authenticate, authorize('admin'), auditLog('incident_delete', 'Incident'), async (req, res) => {
  try {
    const incident = await Incident.findByIdAndDelete(req.params.id);
    if (!incident) return res.status(404).json({ success: false, message: 'Incidência não encontrada.' });
    logger.info({ msg: 'Incident deleted', incidentId: incident._id, by: req.user.email });
    res.json({ success: true, message: 'Incidência eliminada com sucesso!' });
  } catch (error) {
    logger.error({ msg: 'Delete incident error', error });
    res.status(500).json({ success: false, message: 'Erro ao eliminar incidência.' });
  }
});

// ============================================
// 10. NOTÍCIAS
// ============================================

app.get('/api/news', async (_req, res) => {
  try {
    const news = await News.find({ published: true }).select('-author -__v').sort('-publishDate').limit(20);
    res.json({ success: true, count: news.length, data: { news } });
  } catch (error) {
    logger.error({ msg: 'List news error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar notícias.' });
  }
});

app.post('/api/news', authenticate, authorize('moderator', 'admin'), auditLog('news_create', 'News'), async (req, res) => {
  try {
    const { title, excerpt, content, image, published } = req.body;
    const news = await News.create({ title, excerpt, content, image, author: req.user._id, published: !!published, publishDate: published ? Date.now() : null });
    logger.info({ msg: 'News created', by: req.user.email, newsId: news._id });
    res.status(201).json({ success: true, message: 'Notícia criada com sucesso!', data: { news } });
  } catch (error) {
    logger.error({ msg: 'Create news error', error });
    res.status(500).json({ success: false, message: 'Erro ao criar notícia.' });
  }
});

app.put('/api/news/:id', authenticate, authorize('moderator', 'admin'), auditLog('news_update', 'News'), async (req, res) => {
  try {
    const { title, excerpt, content, image, published } = req.body;
    const news = await News.findById(req.params.id);
    if (!news) return res.status(404).json({ success: false, message: 'Notícia não encontrada.' });
    if (title !== undefined) news.title = title;
    if (excerpt !== undefined) news.excerpt = excerpt;
    if (content !== undefined) news.content = content;
    if (image !== undefined) news.image = image;
    if (published !== undefined) { news.published = published; if (published && !news.publishDate) news.publishDate = Date.now(); }
    await news.save();
    logger.info({ msg: 'News updated', newsId: news._id, by: req.user.email });
    res.json({ success: true, message: 'Notícia atualizada com sucesso!', data: { news } });
  } catch (error) {
    logger.error({ msg: 'Update news error', error });
    res.status(500).json({ success: false, message: 'Erro ao atualizar notícia.' });
  }
});

app.delete('/api/news/:id', authenticate, authorize('admin'), auditLog('news_delete', 'News'), async (req, res) => {
  try {
    const news = await News.findByIdAndDelete(req.params.id);
    if (!news) return res.status(404).json({ success: false, message: 'Notícia não encontrada.' });
    logger.info({ msg: 'News deleted', newsId: news._id, by: req.user.email });
    res.json({ success: true, message: 'Notícia eliminada com sucesso!' });
  } catch (error) {
    logger.error({ msg: 'Delete news error', error });
    res.status(500).json({ success: false, message: 'Erro ao eliminar notícia.' });
  }
});

// ============================================
// 11. SLIDES
// ============================================

app.get('/api/slides', async (_req, res) => {
  try {
    const slides = await Slide.find({ active: true }).sort('order').select('-__v');
    res.json({ success: true, count: slides.length, data: { slides } });
  } catch (error) {
    logger.error({ msg: 'List slides error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar slides.' });
  }
});

app.post('/api/slides', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { title, image, order, active } = req.body;
    const slide = await Slide.create({ title, image, order: order || 0, active: active !== undefined ? active : true });
    logger.info({ msg: 'Slide created', by: req.user.email, slideId: slide._id });
    res.status(201).json({ success: true, message: 'Slide criado com sucesso!', data: { slide } });
  } catch (error) {
    logger.error({ msg: 'Create slide error', error });
    res.status(500).json({ success: false, message: 'Erro ao criar slide.' });
  }
});

app.put('/api/slides/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { title, image, order, active } = req.body;
    const slide = await Slide.findByIdAndUpdate(req.params.id, { title, image, order, active }, { new: true, runValidators: true });
    if (!slide) return res.status(404).json({ success: false, message: 'Slide não encontrado.' });
    logger.info({ msg: 'Slide updated', slideId: slide._id, by: req.user.email });
    res.json({ success: true, message: 'Slide atualizado com sucesso!', data: { slide } });
  } catch (error) {
    logger.error({ msg: 'Update slide error', error });
    res.status(500).json({ success: false, message: 'Erro ao atualizar slide.' });
  }
});

app.delete('/api/slides/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const slide = await Slide.findByIdAndDelete(req.params.id);
    if (!slide) return res.status(404).json({ success: false, message: 'Slide não encontrado.' });
    logger.info({ msg: 'Slide deleted', slideId: slide._id, by: req.user.email });
    res.json({ success: true, message: 'Slide eliminado com sucesso!' });
  } catch (error) {
    logger.error({ msg: 'Delete slide error', error });
    res.status(500).json({ success: false, message: 'Erro ao eliminar slide.' });
  }
});

// ============================================
// 12. LINKS
// ============================================

app.get('/api/links', async (_req, res) => {
  try {
    const links = await Link.find({ active: true }).sort('order').select('-__v');
    res.json({ success: true, count: links.length, data: { links } });
  } catch (error) {
    logger.error({ msg: 'List links error', error });
    res.status(500).json({ success: false, message: 'Erro ao carregar links.' });
  }
});

app.post('/api/links', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { title, url, order, active } = req.body;
    const link = await Link.create({ title, url, order: order || 0, active: active !== undefined ? active : true });
    logger.info({ msg: 'Link created', by: req.user.email, linkId: link._id });
    res.status(201).json({ success: true, message: 'Link criado com sucesso!', data: { link } });
  } catch (error) {
    logger.error({ msg: 'Create link error', error });
    res.status(500).json({ success: false, message: 'Erro ao criar link.' });
  }
});

app.put('/api/links/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { title, url, order, active } = req.body;
    const link = await Link.findByIdAndUpdate(req.params.id, { title, url, order, active }, { new: true, runValidators: true });
    if (!link) return res.status(404).json({ success: false, message: 'Link não encontrado.' });
    logger.info({ msg: 'Link updated', linkId: link._id, by: req.user.email });
    res.json({ success: true, message: 'Link atualizado com sucesso!', data: { link } });
  } catch (error) {
    logger.error({ msg: 'Update link error', error });
    res.status(500).json({ success: false, message: 'Erro ao atualizar link.' });
  }
});

app.delete('/api/links/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const link = await Link.findByIdAndDelete(req.params.id);
    if (!link) return res.status(404).json({ success: false, message: 'Link não encontrado.' });
    logger.info({ msg: 'Link deleted', linkId: link._id, by: req.user.email });
    res.json({ success: true, message: 'Link eliminado com sucesso!' });
  } catch (error) {
    logger.error({ msg: 'Delete link error', error });
    res.status(500).json({ success: false, message: 'Erro ao eliminar link.' });
  }
});

// ============================================
// 13. ERROS
// ============================================

app.use('*', (_req, res) => res.status(404).json({ success: false, message: 'Rota não encontrada.' }));
app.use((err, _req, res, _next) => {
  logger.error({ msg: 'Server error', error: err });
  const message = process.env.NODE_ENV === 'production' ? 'Erro interno do servidor.' : err.message;
  res.status(err.status || 500).json({ success: false, message, ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }) });
});

// ============================================
// 14. LIGAÇÃO À BD & ARRANQUE
// ============================================

function clean(v) { return v ? String(v).replace(/^['"]|['"]$/g, '').trim() : v; }
const RAW_MONGO_URI = clean(process.env.MONGODB_URI);
if (!RAW_MONGO_URI) { console.error('❌ ERRO: MONGODB_URI não definida!'); process.exit(1); }

const MASKED_URI = RAW_MONGO_URI.replace(/\/\/([^:]+):([^@]+)@/, '//<user>:<pass>@');
console.log('ENV CHECK → NODE_ENV=', process.env.NODE_ENV || '(unset)');
console.log('ENV CHECK → MONGODB_URI (masked)=', MASKED_URI);

const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;
mongoose.set('strictQuery', false);

mongoose.connect(RAW_MONGO_URI, { serverSelectionTimeoutMS: 10000 })
  .then(() => {
    logger.info({ msg: 'MongoDB conectado com sucesso', uri: MASKED_URI });
    app.listen(PORT, () => {
      logger.info({ msg: 'Servidor iniciado', mode: process.env.NODE_ENV || 'development', port: PORT });
      console.log(`🚀 Servidor iniciado: http://localhost:${PORT}`);
      console.log(`📚 API disponível em: http://localhost:${PORT}/api`);
    });
  })
  .catch((error) => {
    logger.error({ msg: 'Erro ao conectar ao MongoDB', error });
    process.exit(1);
  });

process.on('unhandledRejection', (err) => { logger.error({ msg: 'UNHANDLED REJECTION! Shutting down...', error: err }); process.exit(1); });
process.on('uncaughtException', (err) => { logger.error({ msg: 'UNCAUGHT EXCEPTION! Shutting down...', error: err }); process.exit(1); });
process.on('SIGTERM', () => { logger.info({ msg: 'SIGTERM received. Shutting down gracefully...' }); mongoose.connection.close(() => { logger.info({ msg: 'MongoDB connection closed.' }); process.exit(0); }); });

module.exports = app;
