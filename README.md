# NestJS Authentication & Authorization System

A production-grade authentication and authorization system built with NestJS, MongoDB, and Redis. Features comprehensive RBAC, Google OAuth, secure session management, and enterprise-level security measures.

## 🚀 Features

### Authentication & Authorization
- **Local Authentication** with bcryptjs password hashing
- **Google OAuth 2.0** integration via Passport.js
- **JWT-based** access tokens with short TTL (15m)
- **Refresh token rotation** with reuse detection
- **httpOnly cookies** for secure token storage
- **Role-Based Access Control (RBAC)** with granular permissions

### Security
- **Session Management** with multi-device support
- **OTP-based** email verification and password reset
- **Rate limiting** on sensitive endpoints
- **CSRF protection** ready for admin panel
- **Comprehensive audit logging** for all sensitive operations
- **Automatic session cleanup** and token rotation

### Infrastructure
- **Redis caching** for sessions and rate limiting
- **BullMQ queues** for background email processing
- **MongoDB** with Mongoose ODM
- **Email system** with MJML templates via Nodemailer
- **Health checks** for all dependencies
- **Structured logging** with Pino

### Code Quality
- **Strict TypeScript** configuration
- **ESLint** with comprehensive rules
- **Prettier** code formatting
- **Feature-based** modular architecture
- **Comprehensive error handling**

## 📋 Prerequisites

- Node.js 18+ and npm
- MongoDB 6.0+
- Redis 6.0+
- SMTP server (Titan Email recommended)

## 🛠️ Installation

1. **Clone and install dependencies:**
```bash
git clone <repository-url>
cd nestjs-auth-system
npm install
```

2. **Environment setup:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start dependencies:**
```bash
# MongoDB (if using Docker)
docker run -d --name mongodb -p 27017:27017 mongo:6

# Redis (if using Docker)  
docker run -d --name redis -p 6379:6379 redis:7
```

4. **Run the application:**
```bash
# Development
npm run start:dev

# Production build
npm run build
npm run start:prod
```

## 🔧 Configuration

### Required Environment Variables

```env
# Core
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/auth_system

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT (Generate secure keys!)
JWT_ACCESS_SECRET=your-super-secret-access-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# Email
SMTP_HOST=smtp.titan.email
SMTP_USER=your-email@yourdomain.com
SMTP_PASS=your-email-password
SMTP_FROM=noreply@yourdomain.com

# Application URLs
FRONTEND_URL=http://localhost:3000
ADMIN_URL=http://localhost:3001
```

## 🏗️ Architecture

### Module Structure
```
src/
├── modules/
│   ├── auth/           # Authentication & OAuth
│   ├── users/          # User management
│   ├── roles/          # Role definitions
│   ├── permissions/    # Permission checking
│   ├── sessions/       # Session management
│   ├── otp/           # OTP generation & validation
│   ├── mail/          # Email queue & templates
│   ├── audit/         # Audit logging
│   ├── cache/         # Redis operations
│   ├── queue/         # Background job management
│   └── health/        # Health checks
├── common/
│   ├── decorators/    # Custom decorators
│   ├── guards/        # Authorization guards
│   ├── enums/         # Shared enumerations
│   └── interfaces/    # TypeScript interfaces
└── config/            # Configuration validation
```

### Database Models

**Users Collection:**
```typescript
{
  email: string (unique, lowercase)
  passwordHash?: string
  firstName: string
  lastName: string
  roles: ObjectId[] (ref: Role)
  status: 'active' | 'inactive' | 'suspended' | 'pending'
  isEmailVerified: boolean
  googleId?: string
  avatar?: string
  lastLoginAt?: Date
  lastLoginIp?: string
}
```

**Roles Collection:**
```typescript
{
  name: string (unique)
  description: string
  permissions: string[]
  isActive: boolean
}
```

**Sessions Collection:**
```typescript
{
  userId: ObjectId (ref: User)
  hashedRefreshToken: string
  ip: string
  userAgent: string
  deviceName?: string
  lastSeen: Date
  revoked: boolean
}
```

## 🔐 RBAC Implementation

### Permission Format
Permissions follow the `resource:action` pattern:
- `users:read`, `users:write`, `users:delete`
- `roles:read`, `roles:write`, `roles:assign`
- `leads:*`, `applications:*`, `students:*`
- `system:health`, `system:audit`, `system:queue`
- `*` (super admin - all permissions)

### Default Roles
- **super_admin**: All permissions (`["*"]`)
- **admin**: Most permissions for system management
- **counsellor**: Business operations permissions
- **support**: Read-only access to most resources

### Usage Example
```typescript
@Get('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
@Permissions('users:read')
async getUsers() {
  // Only users with 'users:read' permission can access
}
```

## 📧 Email System

### Templates
Located in `/templates/` directory:
- `email-verification.hbs` - Email verification with OTP
- `welcome.hbs` - Welcome message after verification
- `password-reset.hbs` - Password reset with OTP
- `password-reset-confirmation.hbs` - Confirmation after reset
- `password-change-notification.hbs` - Security notification
- `session-revocation-alert.hbs` - Multiple session revocation
- `role-change-notification.hbs` - Permission changes

### Queue Processing
Emails are processed asynchronously via BullMQ:
- Automatic retries with exponential backoff
- Dead letter queue for failed emails
- Monitoring endpoints for queue health

## 🛡️ Security Features

### Authentication Flow
1. **Registration**: Email + password → OTP verification → Account activation
2. **Login**: Credentials validation → JWT access token + httpOnly refresh cookie
3. **Token Refresh**: Automatic rotation with reuse detection
4. **Logout**: Token revocation + session cleanup

### Session Security
- **Refresh Token Rotation**: New token on each refresh
- **Reuse Detection**: Revokes all user sessions if token reused
- **Multi-device Support**: Track and manage multiple sessions
- **Automatic Cleanup**: TTL-based session expiration

### Rate Limiting
- Login attempts: 10/5min
- OTP requests: 3/5min  
- Password reset: 3/5min
- Registration: 5/5min

## 📊 Monitoring & Health

### Health Endpoints
- `GET /health` - Comprehensive health check
- `GET /health/liveness` - Liveness probe for K8s
- `GET /health/readiness` - Readiness probe for K8s
- `GET /health/info` - System information

### Queue Management
- `GET /queue/health` - Queue status and statistics
- `POST /queue/email/pause` - Pause email processing
- `POST /queue/email/resume` - Resume email processing
- `POST /queue/email/retry-failed` - Retry failed jobs

### Audit System
- Complete audit trail for sensitive operations
- User activity tracking
- Resource change monitoring  
- Configurable retention policies

## 🚦 API Endpoints

### Authentication
```
POST /auth/register              # User registration
POST /auth/login                 # Email/password login
GET  /auth/google                # Google OAuth initiation
GET  /auth/google/callback       # Google OAuth callback
POST /auth/refresh               # Token refresh
POST /auth/logout                # Logout
GET  /auth/me                    # Current user profile
```

### User Management
```
GET    /users                    # List users (admin)
GET    /users/me                 # Current user profile
PATCH  /users/me                 # Update own profile
GET    /users/:id                # Get user by ID (admin)
PATCH  /users/:id                # Update user (admin)
DELETE /users/:id                # Delete user (admin)
PATCH  /users/:id/roles          # Assign roles (admin)
```

### Session Management
```
GET    /sessions/my              # My active sessions
DELETE /sessions/my/:id          # Revoke my session
DELETE /sessions/my/all          # Revoke all my sessions
GET    /sessions/user/:id        # User sessions (admin)
DELETE /sessions/user/:id/all    # Revoke all user sessions (admin)
```

## 🧪 Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## 🏭 Production Deployment

### Docker Setup
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 3000
CMD ["node", "dist/main"]
```

### Environment Checklist
- [ ] Generate secure JWT secrets (256-bit)
- [ ] Configure production MongoDB with replica set
- [ ] Set up Redis cluster for high availability
- [ ] Configure SMTP with proper SPF/DKIM
- [ ] Set appropriate CORS origins
- [ ] Enable HTTPS with proper certificates
- [ ] Configure reverse proxy (nginx/cloudflare)
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up automated backups

### Performance Tuning
- MongoDB: Proper indexing and connection pooling
- Redis: Appropriate memory settings and persistence
- Node.js: PM2 cluster mode for multi-core utilization
- Nginx: Gzip compression and static file serving

## 📈 Scaling Considerations

- **Horizontal Scaling**: Stateless design allows multiple instances
- **Database**: MongoDB sharding for large datasets
- **Cache**: Redis Cluster for distributed caching
- **Queues**: BullMQ supports multiple Redis instances
- **Load Balancing**: Session affinity not required

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Follow the established code style and conventions
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

## 🆘 Support

For questions, issues, or contributions:
- Create an issue in the repository
- Check existing documentation
- Review the code comments for implementation details

---

**Built with ❤️ for production-grade applications**