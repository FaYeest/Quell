const db = {
    query: async (sql, params = []) => {
        // Mock DB query runner for demonstration
        console.log(`[DB Execute]: ${sql} with params:`, params);
        return [{ id: 1, name: "Sample Record" }];
    }
};

// VULNERABILITY 1: SQL Injection (OWASP A03)
// Raw query concatenation using unsanitized user input from req.query.username
async function getUserProfile(req, res) {
    const username = req.query.username;
    
    // UNSAFE: Direct string interpolation into SQL query string
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    const users = await db.query(query);

    if (!users || users.length === 0) {
        return res.status(404).json({ error: "User not found" });
    }

    return res.json({ user: users[0] });
}

// VULNERABILITY 2: Broken Object Level Authorization (IDOR)
// The endpoint is behind authenticateToken, so req.user.orgId is known,
// but the query blindly retrieves the invoice by ID without enforcing tenant/org ownership.
async function getInvoiceDetails(req, res) {
    const invoiceId = req.params.invoiceId;

    // UNSAFE IDOR: Fetches invoice by ID alone without checking req.user.orgId or user ownership
    const invoices = await db.query(
        "SELECT * FROM invoices WHERE id = $1",
        [invoiceId]
    );

    if (!invoices || invoices.length === 0) {
        return res.status(404).json({ error: "Invoice not found" });
    }

    return res.json({ invoice: invoices[0] });
}

module.exports = {
    getUserProfile,
    getInvoiceDetails
};
