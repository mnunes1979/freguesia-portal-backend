// ============================================
// SERVER.JS - Backend Seguro Portal Freguesia
// ============================================

// ⚠️ CRITICAL: Load environment variables FIRST!
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
// DEBUG: Verificar variáveis de ambiente críticas
// ============================================
console.log('============================================');
console.log('🔍 VERIFICAÇÃO DE VARIÁVEIS DE AMBIENTE');
console.log('============================================');
console.log('NODE_ENV:', process.env.NODE_ENV || '(não definido)');
console.log('PORT:', process.env.PORT || '(não definido)');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '✅ Definido' : '❌ NÃO DEFINIDO');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '✅ Definido' : '❌ NÃO DEFINIDO');
console.log('ALLOWED_ORIGINS:', process.env.ALLOWED_ORIGINS || '(não definido - usando defaults)');
console.log('============================================\n');

// ============================================
// 1. CONFIGURAÇÃO DE CORS (ANTES DE TUDO!)
// ============================================

// Lista de origens permitidas
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'https://portal-freguesias-freguesia-frontend.3isjct.easypanel.host',
      'https://portal-freguesias-freguesia-backoffice.3isjct.easypanel.host'
    ];

console.log('🔐 CORS - Origens permitidas:', allowedOrigins);

// Configuração CORS corrigida
const corsOptions = {
  origin: allowedOrigins,
  credentials: false, // ✅ REMOVIDO! Não usamos cookies, só tokens em localStorage
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400 // 24 horas de cache para preflight
};

// ✅ CORS VEM PRIMEIRO! (antes de helmet e de tudo)
app.use(cors(corsOptions));

// ✅ Handler OPTIONS super agressivo (responde IMEDIATAMENTE)
app.options('*', cors(corsOptions));

// Middleware de logging para TODOS os pedidos
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.url} - Origin: ${req.headers.origin || 'N/A'}`);
  next();
});

// Log adicional para OPTIONS
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    console.log('✅ OPTIONS request received and processed');
  }
  next();
});

// ============================================
// 2. SEGURANÇA (DEPOIS DO CORS!)
// ============================================

// ✅ Helmet VEM DEPOIS DO CORS (para não sobrescrever headers)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }, // ✅ IMPORTANTE: permitir cross-origin
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

// ============================================
// 3. ROTA DE HEALTH (ANTES DE RATE LIMITERS!)
// ============================================

// ✅ ROTA DE HEALTH SEM RATE LIMIT (vem ANTES de tudo!)
app.get('/api/health', (req, res) => {
  console.log('✅ Health check accessed! Origin:', req.headers.origin || 'N/A');
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'API is running!',
    cors: {
      origin: req.headers.origin || 'N/A',
      allowedOrigins: allowedOrigins
    }
  });
});

console.log('✅ Health check route registered at /api/health (BEFORE rate limiters)');

// ============================================
// 4. RATE LIMITING
// ============================================

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Demasiados pedidos deste IP, tente novamente mais tarde.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log('⚠️  RATE LIMIT ATINGIDO:', req.method, req.url, 'IP:', req.ip);
    res.status(429).json({ 
      success: false, 
      message: 'Demasiados pedidos deste IP, tente novamente mais tarde.' 
    });
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiadas tentativas de login. Conta temporariamente bloqueada.',
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    console.log('⚠️  AUTH RATE LIMIT ATINGIDO:', req.method, req.url, 'IP:', req.ip);
    res.status(429).json({ 
      success: false, 
      message: 'Demasiadas tentativas de login. Conta temporariamente bloqueada.' 
    });
  }
});

const incidentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Limite de incidências atingido. Tente novamente mais tarde.',
});

// Logging ANTES dos rate limiters
app.use((req, res, next) => {
  console.log(`🔓 BEFORE rate limiters: ${req.method} ${req.url}`);
  next();
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Logging DEPOIS dos rate limiters
app.use((req, res, next) => {
  console.log(`✅ AFTER rate limiters: ${req.method} ${req.url}`);
  next();
});

// ============================================
// 5. LOGGING SEGURO
// ============================================

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json() // JSON com timestamps (ideal para Easypanel)
  ),
  transports: [
    new winston.transports.Console()
  ],
});

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// ============================================
// 5. MODELOS DE DADOS
// ============================================

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Nome é obrigatório'],
    trim: true,
    maxlength: [100, 'Nome muito longo']
  },
  email: {
    type: String,
    required: [true, 'Email é obrigatório'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Email inválido']
  },
  phone: {
    type: String,
    trim: true,
    match: [/^\+?[0-9\s-()]+$/, 'Telefone inválido']
  },
  password: {
    type: String,
    required: [true, 'Password é obrigatória'],
    minlength: [8, 'Password deve ter no mínimo 8 caracteres'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'moderator', 'admin'],
    default: 'user'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date,
  consentGiven: {
    type: Boolean,
    required: true,
    default: false
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

const User = mongoose.model('User', userSchema);

const incidentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Título é obrigatório'],
    trim: true,
    maxlength: [200, 'Título muito longo']
  },
  description: {
    type: String,
    required: [true, 'Descrição é obrigatória'],
    trim: true,
    maxlength: [2000, 'Descrição muito longa']
  },
  location: {
    type: String,
    required: [true, 'Localização é obrigatória'],
    trim: true,
    maxlength: [300, 'Localização muito longa']
  },
  gps: {
    type: String,
    trim: true,
    match: [/^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$/, 'Coordenadas GPS inválidas']
  },
  status: {
    type: String,
    enum: ['pending', 'analyzing', 'inProgress', 'resolved', 'rejected'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  category: {
    type: String,
    enum: ['infrastructure', 'safety', 'environment', 'health', 'other'],
    default: 'other'
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  notes: [{
    text: String,
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  images: [String],
  resolvedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Incident = mongoose.model('Incident', incidentSchema);

const newsSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Título é obrigatório'],
    trim: true,
    maxlength: [200, 'Título muito longo']
  },
  content: {
    type: String,
    required: [true, 'Conteúdo é obrigatório'],
    trim: true
  },
  excerpt: {
    type: String,
    trim: true,
    maxlength: [300, 'Resumo muito longo']
  },
  image: String,
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  published: {
    type: Boolean,
    default: false
  },
  publishedAt: Date,
  views: {
    type: Number,
    default: 0
  },
  category: {
    type: String,
    enum: ['event', 'announcement', 'notice', 'general'],
    default: 'general'
  },
  tags: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const News = mongoose.model('News', newsSchema);

const slideSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Título é obrigatório'],
    trim: true,
    maxlength: [100, 'Título muito longo']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [300, 'Descrição muito longa']
  },
  image: {
    type: String,
    required: [true, 'Imagem é obrigatória']
  },
  link: {
    type: String,
    trim: true
  },
  order: {
    type: Number,
    default: 0
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Slide = mongoose.model('Slide', slideSchema);

const linkSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Título é obrigatório'],
    trim: true,
    maxlength: [100, 'Título muito longo']
  },
  url: {
    type: String,
    required: [true, 'URL é obrigatória'],
    trim: true
  },
  icon: {
    type: String,
    trim: true
  },
  category: {
    type: String,
    enum: ['service', 'external', 'internal', 'document'],
    default: 'external'
  },
  order: {
    type: Number,
    default: 0
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Link = mongoose.model('Link', linkSchema);

const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true
  },
  resource: {
    type: String,
    required: true
  },
  resourceId: mongoose.Schema.Types.ObjectId,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ipAddress: String,
  userAgent: String,
  timestamp: {
    type: Date,
    default: Date.now
  },
  details: mongoose.Schema.Types.Mixed
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ============================================
// 6. MIDDLEWARE DE AUTENTICAÇÃO
// ============================================

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token não fornecido.'
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Utilizador não encontrado.'
      });
    }
    
    if (user.isLocked()) {
      return res.status(403).json({
        success: false,
        message: 'Conta temporariamente bloqueada.'
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Token inválido.'
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expirado.'
      });
    }
    
    logger.error({ msg: 'Authentication error', error });
    res.status(500).json({
      success: false,
      message: 'Erro na autenticação.'
    });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Sem permissões para esta ação.'
      });
    }
    next();
  };
};

const auditLog = (action, resource) => {
  return async (req, res, next) => {
    try {
      await AuditLog.create({
        action,
        resource,
        resourceId: req.params.id,
        user: req.user._id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: {
          method: req.method,
          url: req.url,
          body: req.body
        }
      });
    } catch (error) {
      logger.error({ msg: 'Audit log error', error });
    }
    next();
  };
};

// ============================================
// 7. ROTAS DE AUTENTICAÇÃO
// ============================================

app.post('/api/auth/register', 
  [
    body('name').trim().isLength({ min: 2, max: 100 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('phone').optional().trim(),
    body('consentGiven').isBoolean().equals('true')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Dados inválidos.',
          errors: errors.array()
        });
      }
      
      const { name, email, phone, password, consentGiven } = req.body;
      
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email já registado.'
        });
      }
      
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 horas
      
      const user = await User.create({
        name,
        email,
        phone,
        password,
        consentGiven,
        verificationToken,
        verificationTokenExpires
      });
      
      logger.info({ msg: 'User registered', email });
      
      res.status(201).json({
        success: true,
        message: 'Registo efetuado com sucesso! Verifica o teu email.',
        data: {
          userId: user._id
        }
      });
    } catch (error) {
      logger.error({ msg: 'Register error', error });
      res.status(500).json({
        success: false,
        message: 'Erro ao efetuar registo.'
      });
    }
  }
);

app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.token,
      verificationTokenExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Token inválido ou expirado.'
      });
    }
    
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();
    
    logger.info({ msg: 'User verified', email: user.email });
    
    res.json({
      success: true,
      message: 'Email verificado com sucesso!'
    });
  } catch (error) {
    logger.error({ msg: 'Verify error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao verificar email.'
    });
  }
});

app.post('/api/auth/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Dados inválidos.'
        });
      }
      
      const { email, password } = req.body;
      
      const user = await User.findOne({ email }).select('+password');
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Credenciais inválidas.'
        });
      }
      
      if (user.isLocked()) {
        return res.status(403).json({
          success: false,
          message: 'Conta temporariamente bloqueada. Tenta novamente mais tarde.'
        });
      }
      
      const isPasswordCorrect = await user.comparePassword(password);
      
      if (!isPasswordCorrect) {
        user.loginAttempts += 1;
        
        if (user.loginAttempts >= 5) {
          user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutos
          logger.warn({ msg: 'Account locked due to failed login attempts', email });
        }
        
        await user.save();
        
        return res.status(401).json({
          success: false,
          message: 'Credenciais inválidas.'
        });
      }
      
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      user.lastLogin = Date.now();
      await user.save();
      
      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      logger.info({ msg: 'User logged in', email });
      
      res.json({
        success: true,
        message: 'Login efetuado com sucesso!',
        data: {
          token,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isVerified: user.isVerified
          }
        }
      });
    } catch (error) {
      logger.error({ msg: 'Login error', error });
      res.status(500).json({
        success: false,
        message: 'Erro ao efetuar login.'
      });
    }
  }
);

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  } catch (error) {
    logger.error({ msg: 'Get user error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar utilizador.'
    });
  }
});

// ============================================
// 8. ROTAS DE INCIDÊNCIAS
// ============================================

app.get('/api/incidents/public', async (req, res) => {
  try {
    const { status } = req.query;
    
    const query = status ? { status } : {};
    
    const incidents = await Incident.find(query)
      .populate('user', 'name email')
      .sort('-createdAt')
      .limit(50);
    
    res.json({
      success: true,
      data: { incidents }
    });
  } catch (error) {
    logger.error({ msg: 'Get incidents error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar incidências.'
    });
  }
});

app.get('/api/incidents/my', authenticate, async (req, res) => {
  try {
    const incidents = await Incident.find({ user: req.user._id })
      .sort('-createdAt');
    
    res.json({
      success: true,
      data: { incidents }
    });
  } catch (error) {
    logger.error({ msg: 'Get my incidents error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar incidências.'
    });
  }
});

app.get('/api/incidents/:id', async (req, res) => {
  try {
    const incident = await Incident.findById(req.params.id)
      .populate('user', 'name email phone')
      .populate('assignedTo', 'name email')
      .populate('notes.addedBy', 'name');
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incidência não encontrada.'
      });
    }
    
    res.json({
      success: true,
      data: { incident }
    });
  } catch (error) {
    logger.error({ msg: 'Get incident error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar incidência.'
    });
  }
});

app.post('/api/incidents', authenticate, incidentLimiter,
  [
    body('title').trim().isLength({ min: 5, max: 200 }).escape(),
    body('description').trim().isLength({ min: 10, max: 2000 }).escape(),
    body('location').trim().isLength({ min: 5, max: 300 }).escape(),
    body('gps').optional().trim(),
    body('category').isIn(['infrastructure', 'safety', 'environment', 'health', 'other'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Dados inválidos.',
          errors: errors.array()
        });
      }
      
      const incident = await Incident.create({
        ...req.body,
        user: req.user._id
      });
      
      logger.info({ msg: 'Incident created', user: req.user.email, incident: incident._id });
      
      res.status(201).json({
        success: true,
        message: 'Incidência criada com sucesso!',
        data: { incident }
      });
    } catch (error) {
      logger.error({ msg: 'Create incident error', error });
      res.status(500).json({
        success: false,
        message: 'Erro ao criar incidência.'
      });
    }
  }
);

app.patch('/api/incidents/:id/status', authenticate, authorize('moderator', 'admin'), auditLog('incident_update', 'Incident'), async (req, res) => {
  try {
    const { status, note } = req.body;
    
    if (!['pending', 'analyzing', 'inProgress', 'resolved', 'rejected'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status inválido.'
      });
    }
    
    const incident = await Incident.findById(req.params.id);
    
    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incidência não encontrada.'
      });
    }
    
    incident.status = status;
    
    if (status === 'resolved') {
      incident.resolvedAt = Date.now();
    }
    
    if (note) {
      incident.notes.push({
        text: note,
        addedBy: req.user._id
      });
    }
    
    await incident.save();
    
    logger.info({ msg: 'Incident status updated', incident: incident._id, status, by: req.user.email });
    
    res.json({
      success: true,
      message: 'Status atualizado com sucesso!',
      data: { incident }
    });
  } catch (error) {
    logger.error({ msg: 'Update incident status error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar status.'
    });
  }
});

// ============================================
// 9. ROTAS DE NOTÍCIAS
// ============================================

app.get('/api/news', async (req, res) => {
  try {
    const { published } = req.query;
    
    const query = published === 'true' ? { published: true } : {};
    
    const news = await News.find(query)
      .populate('author', 'name')
      .sort('-createdAt')
      .limit(50);
    
    res.json({
      success: true,
      data: { news }
    });
  } catch (error) {
    logger.error({ msg: 'Get news error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar notícias.'
    });
  }
});

app.get('/api/news/:id', async (req, res) => {
  try {
    const news = await News.findById(req.params.id)
      .populate('author', 'name email');
    
    if (!news) {
      return res.status(404).json({
        success: false,
        message: 'Notícia não encontrada.'
      });
    }
    
    news.views += 1;
    await news.save();
    
    res.json({
      success: true,
      data: { news }
    });
  } catch (error) {
    logger.error({ msg: 'Get news by id error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar notícia.'
    });
  }
});

app.post('/api/news', authenticate, authorize('moderator', 'admin'), auditLog('news_create', 'News'),
  [
    body('title').trim().isLength({ min: 5, max: 200 }).escape(),
    body('content').trim().isLength({ min: 10 }),
    body('excerpt').optional().trim().isLength({ max: 300 }).escape(),
    body('category').isIn(['event', 'announcement', 'notice', 'general'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Dados inválidos.',
          errors: errors.array()
        });
      }
      
      const news = await News.create({
        ...req.body,
        author: req.user._id
      });
      
      logger.info({ msg: 'News created', author: req.user.email, news: news._id });
      
      res.status(201).json({
        success: true,
        message: 'Notícia criada com sucesso!',
        data: { news }
      });
    } catch (error) {
      logger.error({ msg: 'Create news error', error });
      res.status(500).json({
        success: false,
        message: 'Erro ao criar notícia.'
      });
    }
  }
);

app.put('/api/news/:id', authenticate, authorize('moderator', 'admin'), auditLog('news_update', 'News'), async (req, res) => {
  try {
    const news = await News.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!news) {
      return res.status(404).json({
        success: false,
        message: 'Notícia não encontrada.'
      });
    }
    
    logger.info({ msg: 'News updated', news: news._id, by: req.user.email });
    
    res.json({
      success: true,
      message: 'Notícia atualizada com sucesso!',
      data: { news }
    });
  } catch (error) {
    logger.error({ msg: 'Update news error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar notícia.'
    });
  }
});

app.delete('/api/news/:id', authenticate, authorize('moderator', 'admin'), auditLog('news_delete', 'News'), async (req, res) => {
  try {
    const news = await News.findByIdAndDelete(req.params.id);
    
    if (!news) {
      return res.status(404).json({
        success: false,
        message: 'Notícia não encontrada.'
      });
    }
    
    logger.info({ msg: 'News deleted', news: news._id, by: req.user.email });
    
    res.json({
      success: true,
      message: 'Notícia eliminada com sucesso!'
    });
  } catch (error) {
    logger.error({ msg: 'Delete news error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao eliminar notícia.'
    });
  }
});

// ============================================
// 10. ROTAS DE SLIDES
// ============================================

app.get('/api/slides', async (req, res) => {
  try {
    const slides = await Slide.find({ active: true })
      .sort('order');
    
    res.json({
      success: true,
      data: { slides }
    });
  } catch (error) {
    logger.error({ msg: 'Get slides error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar slides.'
    });
  }
});

app.post('/api/slides', authenticate, authorize('admin'), auditLog('slide_create', 'Slide'), async (req, res) => {
  try {
    const slide = await Slide.create(req.body);
    
    logger.info({ msg: 'Slide created', by: req.user.email });
    
    res.status(201).json({
      success: true,
      message: 'Slide criado com sucesso!',
      data: { slide }
    });
  } catch (error) {
    logger.error({ msg: 'Create slide error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao criar slide.'
    });
  }
});

app.put('/api/slides/:id', authenticate, authorize('admin'), auditLog('slide_update', 'Slide'), async (req, res) => {
  try {
    const slide = await Slide.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!slide) {
      return res.status(404).json({
        success: false,
        message: 'Slide não encontrado.'
      });
    }
    
    logger.info({ msg: 'Slide updated', by: req.user.email });
    
    res.json({
      success: true,
      message: 'Slide atualizado com sucesso!',
      data: { slide }
    });
  } catch (error) {
    logger.error({ msg: 'Update slide error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar slide.'
    });
  }
});

app.delete('/api/slides/:id', authenticate, authorize('admin'), auditLog('slide_delete', 'Slide'), async (req, res) => {
  try {
    const slide = await Slide.findByIdAndDelete(req.params.id);
    
    if (!slide) {
      return res.status(404).json({
        success: false,
        message: 'Slide não encontrado.'
      });
    }
    
    logger.info({ msg: 'Slide deleted', by: req.user.email });
    
    res.json({
      success: true,
      message: 'Slide eliminado com sucesso!'
    });
  } catch (error) {
    logger.error({ msg: 'Delete slide error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao eliminar slide.'
    });
  }
});

// ============================================
// 11. ROTAS DE LINKS
// ============================================

app.get('/api/links', async (req, res) => {
  try {
    const links = await Link.find({ active: true })
      .sort('order');
    
    res.json({
      success: true,
      data: { links }
    });
  } catch (error) {
    logger.error({ msg: 'Get links error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar links.'
    });
  }
});

app.post('/api/links', authenticate, authorize('admin'), auditLog('link_create', 'Link'), async (req, res) => {
  try {
    const link = await Link.create(req.body);
    
    logger.info({ msg: 'Link created', by: req.user.email });
    
    res.status(201).json({
      success: true,
      message: 'Link criado com sucesso!',
      data: { link }
    });
  } catch (error) {
    logger.error({ msg: 'Create link error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao criar link.'
    });
  }
});

app.put('/api/links/:id', authenticate, authorize('admin'), auditLog('link_update', 'Link'), async (req, res) => {
  try {
    const link = await Link.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!link) {
      return res.status(404).json({
        success: false,
        message: 'Link não encontrado.'
      });
    }
    
    logger.info({ msg: 'Link updated', by: req.user.email });
    
    res.json({
      success: true,
      message: 'Link atualizado com sucesso!',
      data: { link }
    });
  } catch (error) {
    logger.error({ msg: 'Update link error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar link.'
    });
  }
});

app.delete('/api/links/:id', authenticate, authorize('admin'), auditLog('link_delete', 'Link'), async (req, res) => {
  try {
    const link = await Link.findByIdAndDelete(req.params.id);
    
    if (!link) {
      return res.status(404).json({
        success: false,
        message: 'Link não encontrado.'
      });
    }
    
    logger.info({ msg: 'Link deleted', by: req.user.email });
    
    res.json({
      success: true,
      message: 'Link eliminado com sucesso!'
    });
  } catch (error) {
    logger.error({ msg: 'Delete link error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao eliminar link.'
    });
  }
});

// ============================================
// 12. ROTAS DE ADMINISTRAÇÃO
// ============================================

app.get('/api/admin/users', authenticate, authorize('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password').sort('-createdAt');
    
    res.json({
      success: true,
      data: { users }
    });
  } catch (error) {
    logger.error({ msg: 'Get users error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar utilizadores.'
    });
  }
});

app.patch('/api/admin/users/:id/role', authenticate, authorize('admin'), auditLog('user_update', 'User'), async (req, res) => {
  try {
    const { role } = req.body;
    
    if (!['user', 'moderator', 'admin'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Role inválida.'
      });
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilizador não encontrado.'
      });
    }
    
    logger.info({ msg: 'User role updated', user: user.email, role, by: req.user.email });
    
    res.json({
      success: true,
      message: 'Role atualizada com sucesso!',
      data: { user }
    });
  } catch (error) {
    logger.error({ msg: 'Update user role error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar role.'
    });
  }
});

app.delete('/api/admin/users/:id', authenticate, authorize('admin'), auditLog('user_delete', 'User'), async (req, res) => {
  try {
    if (req.params.id === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        message: 'Não pode eliminar a sua própria conta.'
      });
    }
    
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilizador não encontrado.'
      });
    }
    
    await Incident.deleteMany({ user: user._id });
    
    logger.info({ msg: 'User deleted', user: user.email, by: req.user.email });
    
    res.json({
      success: true,
      message: 'Utilizador eliminado com sucesso!'
    });
  } catch (error) {
    logger.error({ msg: 'Delete user error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao eliminar utilizador.'
    });
  }
});

app.get('/api/admin/stats', authenticate, authorize('moderator', 'admin'), async (req, res) => {
  try {
    const [
      totalUsers,
      totalIncidents,
      pendingIncidents,
      analyzingIncidents,
      inProgressIncidents,
      resolvedIncidents,
      totalNews,
      publishedNews
    ] = await Promise.all([
      User.countDocuments(),
      Incident.countDocuments(),
      Incident.countDocuments({ status: 'pending' }),
      Incident.countDocuments({ status: 'analyzing' }),
      Incident.countDocuments({ status: 'inProgress' }),
      Incident.countDocuments({ status: 'resolved' }),
      News.countDocuments(),
      News.countDocuments({ published: true })
    ]);
    
    res.json({
      success: true,
      data: {
        users: {
          total: totalUsers
        },
        incidents: {
          total: totalIncidents,
          pending: pendingIncidents,
          analyzing: analyzingIncidents,
          inProgress: inProgressIncidents,
          resolved: resolvedIncidents
        },
        news: {
          total: totalNews,
          published: publishedNews
        }
      }
    });
  } catch (error) {
    logger.error({ msg: 'Get stats error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar estatísticas.'
    });
  }
});

app.get('/api/admin/audit-logs', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, action, userId } = req.query;
    
    const query = {};
    if (action) query.action = action;
    if (userId) query.user = userId;
    
    const logs = await AuditLog.find(query)
      .populate('user', 'name email')
      .sort('-timestamp')
      .limit(Number(limit))
      .skip((Number(page) - 1) * Number(limit));
    
    const count = await AuditLog.countDocuments(query);
    
    res.json({
      success: true,
      data: {
        logs,
        totalPages: Math.ceil(count / Number(limit)),
        currentPage: Number(page)
      }
    });
  } catch (error) {
    logger.error({ msg: 'Get audit logs error', error });
    res.status(500).json({
      success: false,
      message: 'Erro ao carregar logs.'
    });
  }
});

// ============================================
// 13. TRATAMENTO DE ERROS
// ============================================

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Rota não encontrada.'
  });
});

app.use((err, req, res, next) => {
  logger.error({ msg: 'Server error', error: err });
  
  const message = process.env.NODE_ENV === 'production' 
    ? 'Erro interno do servidor.' 
    : err.message;
  
  res.status(err.status || 500).json({
    success: false,
    message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// ============================================
// 14. LIGAÇÃO À BASE DE DADOS E SERVIDOR
// ============================================

function clean(value) {
  if (!value) return value;
  return String(value).replace(/^['"]|['"]$/g, '').trim().replace(/\s+$/,'').replace(/\$$/, '');
}

const RAW_MONGO_URI = clean(process.env.MONGODB_URI);
if (!RAW_MONGO_URI) {
  console.error('❌ ERRO: Variável MONGODB_URI não definida no ambiente!');
  process.exit(1);
}

const MASKED_URI = RAW_MONGO_URI.replace(/\/\/([^:]+):([^@]+)@/, '//<user>:<pass>@');
console.log('ENV CHECK → NODE_ENV=', process.env.NODE_ENV || '(unset)');
console.log('ENV CHECK → MONGODB_URI (masked)=', MASKED_URI);

const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;
const MONGODB_URI = RAW_MONGO_URI;

mongoose.set('strictQuery', false);

mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 })
  .then(() => {
    logger.info({ msg: 'MongoDB conectado com sucesso', uri: MASKED_URI });
    console.log('✅ MongoDB connection successful!');
    
    app.listen(PORT, () => {
      logger.info({ msg: 'Servidor iniciado', mode: process.env.NODE_ENV || 'development', port: PORT });
      console.log(`🚀 Servidor iniciado: http://localhost:${PORT}`);
      console.log(`📚 API disponível em: http://localhost:${PORT}/api`);
      console.log('✅ Server is listening and ready to accept requests');
      
      setTimeout(() => {
        console.log('✅ Server has been running for 2 seconds without crashes!');
      }, 2000);
    });
  })
  .catch((error) => {
    console.error('❌ MongoDB connection failed!');
    console.error('Error:', error);
    logger.error({ msg: 'Erro ao conectar ao MongoDB', error });
    process.exit(1);
  });

process.on('unhandledRejection', (err) => {
  console.error('❌ UNHANDLED REJECTION DETECTED!');
  console.error('Error:', err);
  logger.error({ msg: 'UNHANDLED REJECTION! Shutting down...', error: err });
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION DETECTED!');
  console.error('Error:', err);
  logger.error({ msg: 'UNCAUGHT EXCEPTION! Shutting down...', error: err });
  process.exit(1);
});

process.on('SIGTERM', async () => {
  logger.info({ msg: 'SIGTERM received. Shutting down gracefully...' });
  try {
    await mongoose.connection.close();
    logger.info({ msg: 'MongoDB connection closed.' });
    process.exit(0);
  } catch (err) {
    logger.error({ msg: 'Error closing MongoDB connection', error: err });
    process.exit(1);
  }
});

module.exports = app;
