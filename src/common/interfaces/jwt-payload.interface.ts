export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
  sessionId: string;
  iat?: number;
  exp?: number;
}