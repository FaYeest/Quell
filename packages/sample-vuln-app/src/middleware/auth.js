// Auth middleware that simulates token authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: "Missing authorization header" });
    }

    // Decodes token and binds authenticated user & organization identity
    req.user = {
        id: req.headers['x-user-id'] || 'usr_default_123',
        orgId: req.headers['x-org-id'] || 'org_acme_corp',
        role: 'member'
    };

    next();
}

module.exports = { authenticateToken };
