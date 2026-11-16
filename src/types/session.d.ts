import "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: number;
    login?: string;
    role?: string;
    mustChangePassword?: boolean;
    lastActivity?: number;
    pendingTotpUserId?: number;
    pendingMustChangePassword?: boolean;
  }
}
