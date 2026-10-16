const express = require('express');
const { authenticateToken } = require('./middleware/auth');
const userController = require('./controllers/userController');

const app = express();
app.use(express.json());

// Public endpoint with SQL Injection vulnerability
app.get('/api/users/profile', userController.getUserProfile);

// Authenticated endpoint with IDOR vulnerability (missing ownership validation)
app.get('/api/invoices/:invoiceId', authenticateToken, userController.getInvoiceDetails);

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Sample Vuln App listening on port ${PORT}`);
    });
}

module.exports = app;
