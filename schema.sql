CREATE TYPE access AS ENUM ('USER', 'ADMIN', 'MANAGER');
CREATE TABLE users (
    "id" serial PRIMARY KEY,
    "email" text UNIQUE,
    "firstName" text,
    "lastName" text,
    "phone" text UNIQUE,
    "avatar" text,
    "access" access DEFAULT 'USER',
    "active" boolean DEFAULT FALSE,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP WITH TIME ZONE
);
CREATE TABLE passwords (
    "userId" integer REFERENCES users (id) ON DELETE CASCADE UNIQUE,
    "passwordHash" text
);
CREATE TABLE sessions (
    "userId" integer REFERENCES users (id) ON DELETE CASCADE UNIQUE,
    "fingerprint" text UNIQUE,
    "userAgent" text,
    "ip" text,
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);