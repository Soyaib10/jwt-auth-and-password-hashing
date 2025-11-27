## Understanding Password Hashing

When building authentication systems, you'll hear "never store passwords in plain text" everywhere. But why? And what's the alternative? Let me break it down.

### The Problem with Storing Plain Passwords

Imagine your database looks like this:

```
| id | email             | password |
|----|------------------|----------|
| 1  | soyaib@gmail.com  | soyaib   |
| 2  | zihad@gmail.com   | zihad    |
```

If someone hacks your database (or even a developer with access looks), they can see everyone's passwords. Worse, people reuse passwords across sites. So now the attacker can try these passwords on Gmail, Facebook, banking apps, etc.

### Enter Password Hashing

Instead of storing the actual password, we store a "hash" - a scrambled version that can't be reversed back to the original password.

Here's what your database should look like:

```
| id | email             | password_hash                                                   |
|----|------------------|-----------------------------------------------------------------|
| 1  | soyaib@gmail.com  | $2a$10$N9qo8uLOickgx2ZMRZoMye.IjefVqrEzNhGhqh7YnIeIhtf4Qx3fO   |
| 2  | zihad@gmail.com   | $2a$10$rKjYZ.lXqCJ8qPdnXnFbqOeW9T1VU6V5nOw1wXkKtCeFbZopVpGy6   |
```

Even if someone steals this database, those hashes are useless. You can't log in with a hash, and you can't reverse it to get the original password.

### How Hashing Works

Think of hashing like a meat grinder. You put in a steak (password), and out comes ground beef (hash). You can't reconstruct the steak from the ground beef - it's a one-way process.

```
"soyaib" → [HASH FUNCTION] → "$2a$10$N9qo8uLOickgx2ZMRZoMye..."
```

But here's the magic: if you put the same steak through the grinder the same way, you get the same ground beef. So when Soyaib logs in:

1. He types "soyaib"
2. We hash it the same way
3. We compare the new hash with the stored hash
4. If they match, he's authenticated!

### Why bcrypt?

We use bcrypt specifically because it's designed to be slow and secure. Here's why that matters:

**1. It's Intentionally Slow**

Hashing a password with bcrypt takes about 100 milliseconds. For a legitimate user logging in once, that's fine. But for an attacker trying to guess passwords?

* Trying 1 million passwords = 100,000 seconds = 27 hours
* With a fast hash like MD5, this would take seconds

**2. It Uses Salt**

A "salt" is random data added to your password before hashing. Here's why it's crucial:

Without salt:

```
"soyaib" → always produces → "same_hash_xyz"
```

If two users have the same password, they'd have the same hash. An attacker could use "rainbow tables" (pre-computed hashes of common passwords) to crack them instantly.

With salt:

```
"soyaib" + "random_salt_abc" → "hash_version_1"
"soyaib" + "random_salt_xyz" → "hash_version_2"
```

Same password, different hashes! Each user gets a unique salt, so even if they use the same password, the hashes are different. Rainbow tables become useless.

**3. It's Adaptive**

bcrypt has a "cost factor" that determines how many times it runs the hashing algorithm. As computers get faster, you can increase the cost to keep it slow enough to resist attacks.

### The bcrypt Hash Format

When you see a bcrypt hash like this:

```
$2a$10$N9qo8uLOickgx2ZMRZoMye.IjefVqrEzNhGhqh7YnIeIhtf4Qx3fO
```

It's actually three parts:

* `$2a$` - bcrypt algorithm version
* `10` - cost factor (2^10 = 1,024 iterations)
* `N9qo8uLOickgx2ZMRZoMye` - the salt (encoded)
* `.IjefVqrEzNhGhqh7YnIeIhtf4Qx3fO` - the actual hash

The salt is stored right in the hash! This is intentional. It's not a secret - the security comes from the hashing algorithm itself, not from hiding the salt.

### Registration Flow

When a user registers:

```
1. User submits: email="soyaib@gmail.com", password="soyaib"

2. Server generates salt: "N9qo8uLOickgx2ZMRZoMye"

3. Server combines: "soyaib" + "N9qo8uLOickgx2ZMRZoMye"

4. Server hashes it 1,024 times (cost=10)

5. Result: "$2a$10$N9qo8uLOickgx2ZMRZoMye.IjefVqrEzNhGhqh7YnIeIhtf4Qx3fO"

6. Database stores: email + hash (NOT the original password)
```

### Login Flow

When a user logs in:

```
1. User submits: email="soyaib@gmail.com", password="soyaib"

2. Server finds user in database by email

3. Server retrieves stored hash: "$2a$10$N9qo8uLOickgx2ZMRZoMye..."

4. Server extracts salt from hash: "N9qo8uLOickgx2ZMRZoMye"

5. Server hashes submitted password with that salt

6. Server compares: new hash vs stored hash

7. If they match → login successful!
   If they don't → wrong password
```

Notice we never decrypt or reverse the hash. We just hash the login attempt the same way and compare.

### 1. HashPassword Function

```go
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
```

**What happens:**

* Takes plain text password (e.g., "soyaib")
* `bcrypt.GenerateFromPassword()` does several things:

  * Generates a random salt
  * Combines password + salt
  * Runs it through bcrypt multiple times (cost factor = 10 by default)
  * Returns a hash like: `$2a$10$N9qo8uLOickgx2ZMRZoMye.IjefVqrEzNhGhqh7YnIeIhtf4Qx3fO`

**Why bcrypt?**

* **Slow by design**: Takes ~100ms to hash. Prevents brute-force attacks.
* **Includes salt**: Same password → different hash each time.
* **Adaptive**: Cost factor can be increased as computers get faster.

**Example:**

Input: `"soyaib"`
Output: `$2a$10$rKjYZ.lXqCJ8qPdnXnFbqOeW9T1VU6V5nOw1wXkKtCeFbZopVpGy6`

Same input again → different hash because salt changes.

### 2. CheckPassword Function

```go
func CheckPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
```

**What happens:**

* Takes stored hash from database
* Takes password user typed during login
* bcrypt extracts the salt from stored hash
* Hashes typed password with same salt
* Compares the two hashes
* Returns `nil` if match, error if no match

**Example Flow:**

Stored hash: `$2a$10$rKjYZ.lXqCJ8qPdnXnFbqOeW9T1VU6V5nOw1wXkKtCeFbZopVpGy6`
User types: `"soyaib"`

bcrypt:

1. Extracts salt from stored hash
2. Hashes `"soyaib"` with that salt
3. Compares result with stored hash
4. Returns `nil` (success) or error (wrong password)


*JWT PART:
What are claims?
- Claims are the data you want to store in the token
- user_id: So we know who this token belongs to
- email: Additional user info
- exp: Expiration time (24 hours from now, in Unix timestamp)

Example:
go
claims = {
  "user_id": 1,
  "email": "alice@example.com",
  "exp": 1732800960  // Unix timestamp for 24 hours from now
}


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


go
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
return token.SignedString([]byte(h.JWTSecret))


What happens:
1. Create a new JWT token with HS256 algorithm (HMAC with SHA-256)
2. Sign it with your secret key from .env
3. Return the signed token string

The JWT token has 3 parts (separated by dots):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwiZXhwIjoxNzMyODAwOTYwfQ.signature_here


1. Header (algorithm and token type)
2. Payload (your claims - user_id, email, exp)
3. Signature (proves the token wasn't tampered with)

Important: The payload is NOT encrypted, just base64 encoded. Anyone can 
decode and read it. But they can't modify it without the secret key, 
because the signature would become invalid.

## Flow

**Registration:**

1. Client → `POST /api/register`
   Body: `{"email": "soyaib@gmail.com", "password": "soyaib"}`

2. Server → Parse JSON

3. Server → Hash `"soyaib"` with bcrypt
   Result: `"$2a$10$N9qo8uLOickgx2ZMRZoMye..."`

4. Server → Insert into database

   ```sql
   INSERT INTO users (email, password_hash) VALUES (...)
   ```

5. Server → Return user
   Response:

   ```json
   {"id": 1, "email": "soyaib@gmail.com", "created_at": "..."}
   ```

---

**Login:**

1. Client → `POST /api/login`
   Body: `{"email": "soyaib@gmail.com", "password": "soyaib"}`

2. Server → Find user by email

   ```sql
   SELECT * FROM users WHERE email = 'soyaib@gmail.com'
   ```

3. Server → Compare password with hash

   ```go
   bcrypt.CompareHashAndPassword(stored_hash, "soyaib")
   ```

4. Server → Generate JWT token
   Token contains:

   ```json
   { "user_id": 1, "email": "soyaib@gmail.com", "exp": ... }
   ```

   Signed with secret key

5. Server → Return token + user
   Response:

   ```json
   {
     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "user": { "id": 1, "email": "soyaib@gmail.com", "created_at": "..." }
   }
   ```

6. Client → Store token (usually in `localStorage` or cookie)

7. Client → Send token with future requests
   Header:

   ```
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```


# Middleware part

```
GET /api/protected HTTP/1.1
Host: localhost:8080
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

Request header and JWT header are not same things. In request header you will see a key named Authorization. The value of that key contains a string with a space. Bearer, basicly says the holder of this token is authorized to access this resource and the jwt token itself. That jwt token contains 3 parts. HEADER.PAYLOAD.SIGNATURE

HEADER: {
  "alg": "HS256",
  "typ": "JWT"
}

PAYLOAD: {
   "name": soyaib,
   ...
}

SECRET: HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)

```
ctx := context.WithValue(r.Context(), UserContextKey, claims)
next.ServeHTTP(w, r.WithContext(ctx))
```

## Line 1: `ctx := context.WithValue(r.Context(), UserContextKey, claims)`

This creates a new context with the JWT claims attached to it.

### What's happening:

`r.Context()`

* Gets the current request's context
* Every HTTP request in Go has a context attached to it
* Think of context as a "bag" that travels with the request through all handlers

`UserContextKey`

* This is the "key" to store data in the context
* Defined earlier as: `const UserContextKey contextKey = "user"`
* It's like a label on a box: "This box contains user data"

`claims`

* The JWT claims we extracted:
  `{user_id: 1, email: "soyaib@gmail.com", exp: 1732800960}`
* This is the actual data we want to store

`context.WithValue(...)`

* Creates a NEW context (doesn't modify the old one)
* Stores claims under the key `UserContextKey`
* Returns the new context

Visual representation:
Original context: `{}`

After `WithValue`:

```json
{
  "user": {
    "user_id": 1,
    "email": "soyaib@gmail.com",
    "exp": 1732800960
  }
}
```

---

## Line 2: `next.ServeHTTP(w, r.WithContext(ctx))`

This passes the request to the next handler with the updated context.

### What's happening:

`next`

* This is the next handler in the chain
* Could be another middleware or the final handler
* Example: your protected route handler

`r.WithContext(ctx)`

* Takes the original request `r`
* Replaces its context with our new context `ctx` (the one with claims)
* Returns a new request object with the updated context

`next.ServeHTTP(w, r.WithContext(ctx))`

* Calls the next handler
* Passes the response writer `w` and the modified request
* The next handler can now access the claims from the context



## How to retrieve the claims in your handler:

```go
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get claims from context
    claims := r.Context().Value(middleware.UserContextKey).(jwt.MapClaims)
    
    // Access user data
    userID := claims["user_id"].(float64)  // JWT stores numbers as float64
    email := claims["email"].(string)
    
    fmt.Fprintf(w, "Hello user %v with email %s", userID, email)
}
```

## Complete flow visualization:

1. Client sends request with JWT token
   ↓
2. Middleware extracts and verifies token
   ↓
3. Middleware gets claims: `{user_id: 1, email: "..."}`
   ↓
4. `ctx := context.WithValue(r.Context(), UserContextKey, claims)`
   Creates new context with claims attached
   ↓
5. `next.ServeHTTP(w, r.WithContext(ctx))`
   Passes request with new context to next handler
   ↓
6. Handler retrieves claims from context

   ```go
   claims := r.Context().Value(UserContextKey)
   ```

   ↓
7. Handler uses `user_id` and `email` to process request



