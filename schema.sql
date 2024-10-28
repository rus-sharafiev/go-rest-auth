CREATE TYPE "Access" AS ENUM ('USER', 'ADMIN', 'MANAGER');
CREATE TABLE "User" (
    "id" serial PRIMARY KEY,
    "email" text UNIQUE,
    "firstName" text,
    "lastName" text,
    "phone" text UNIQUE,
    "avatar" text,
    "access" "Access" DEFAULT 'USER',
    "active" boolean DEFAULT FALSE,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP WITH TIME ZONE
);
CREATE TABLE "Password" (
    "userId" integer REFERENCES "User" (id) ON DELETE CASCADE UNIQUE,
    "passwordHash" text
);
CREATE TABLE "Session" (
    "userId" integer REFERENCES "User" (id) ON DELETE CASCADE UNIQUE,
    "fingerprint" text UNIQUE,
    "userAgent" text,
    "ip" text,
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);