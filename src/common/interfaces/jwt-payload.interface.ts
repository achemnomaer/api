export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  sessionId: string;
  aud: string; // audience: 'web' | 'admin'
  iss: string; // issuer
  jti: string; // JWT ID (unique token identifier)
  iat?: number;
  exp?: number;
}