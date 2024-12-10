CREATE TYPE access AS ENUM ('USER', 'ADMIN', 'MANAGER');
CREATE TABLE users (
    id serial PRIMARY KEY,
    email text UNIQUE,
    first_name text,
    last_name text,
    phone text UNIQUE,
    avatar text,
    access Access DEFAULT 'USER',
    active boolean DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE TABLE passwords (
    user_id integer REFERENCES User (id) ON DELETE CASCADE UNIQUE,
    password_hash text
);
CREATE TABLE sessions (
    user_id integer REFERENCES User (id) ON DELETE CASCADE UNIQUE,
    fingerprint text UNIQUE,
    user_agent text,
    ip text,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);