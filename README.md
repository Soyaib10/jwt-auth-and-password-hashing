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

---

## Project Structure

```
.
├── cmd
│   └── api
│       └── main.go              # Application entry point
├── internal
│   ├── config
│   │   └── config.go            # Environment configuration
│   ├── database
│   │   └── postgres.go          # Database connection pool
│   ├── handlers
│   │   └── auth.go              # Registration & login handlers
│   ├── middleware
│   │   └── auth.go              # JWT authentication middleware
│   └── models
│       └── user.go              # User model & password functions
├── .env                          # Environment variables
├── go.mod
└── README.md
```

