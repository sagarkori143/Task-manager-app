const jwt = require('jsonwebtoken');

// Middleware function to authenticate the JWT token
const authenticateJWT = (req, res, next) => {
    // Get the JWT token from the cookies
    const token = req.cookies.authToken;

    // If no token is found in cookies, return a 401 Unauthorized error
    if (!token) {
        return res.status(401).json({ error: "Login Required" });
    }

    // Verify the JWT token using the secret key
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
        if (err) {
            // If the token is invalid or expired, return a 403 Forbidden error
            return res.status(403).json({ error: "Invalid or Expired Token" });
        }
        // Attach the user data (decoded from token) to the request object
        req.user = user;
        next(); // Proceed to the next middleware or route handler
    });
};

// Export the middleware to use it in other parts of the app
module.exports = authenticateJWT;
