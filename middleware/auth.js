const jwt = require('jsonwebtoken');

// Middleware function to protect routes
// This runs before the actual route handler
const protect = (req, res, next) => {
  // Get token from cookies OR Authorization header
  let token = req.cookies.token;
  
  if (!token && req.headers.authorization) {
    token = req.headers.authorization.split(' ')[1];
  }
  
  // If no token found, deny access
  if (!token) {
    return res.status(401).json({ error: 'Not authorized. No token found.' });
  }
  
  try {
    // Verify the token is valid
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add userId to request object for use in route handler
    req.userId = decoded.id;
    
    // Continue to the actual route handler
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Not authorized. Invalid token.' });
  }
};

module.exports = { protect };
