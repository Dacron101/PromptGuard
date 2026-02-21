/**
 * server.js
 * Express server for the Agentic Early Warning System.
 *
 * Endpoints:
 *   GET  /api/forecast/:userId   — Run quant prediction model
 *   POST /api/intervene/:userId  — Run quant + Claude agent + Stripe executor
 */

require('dotenv').config();

const express = require('express');
const path = require('path');
const admin = require('firebase-admin');
const { runForecast } = require('./utils/predictor');
const { runAgentAnalysis } = require('./utils/agent');
const { executeAgentPlan } = require('./utils/executor');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Firebase Initialization ---
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        }),
    });
}

const db = admin.firestore();

// ============================================================
// HELPER: Load user data + transactions from Firestore
// ============================================================
async function loadUserData(userId) {
    const userRef = db.collection('users').doc(userId);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
        const err = new Error(`User "${userId}" not found in Firestore.`);
        err.statusCode = 404;
        throw err;
    }

    const userData = userSnap.data();

    // Load all transactions from sub-collection
    const txSnap = await userRef.collection('transactions').get();
    const transactions = txSnap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    return { userData, transactions };
}

// ============================================================
// GET /api/forecast/:userId
// Runs the quant forecasting model and returns raw prediction.
// ============================================================
app.get('/api/forecast/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(`\n📊 [GET /api/forecast/${userId}] Running quant model...`);

    try {
        const { userData, transactions } = await loadUserData(userId);
        const forecast = runForecast(userData, transactions);

        console.log(`   isAtRiskOfDefault: ${forecast.isAtRiskOfDefault}`);
        console.log(`   Forecasted Balance: $${forecast.forecastedBalance}`);

        res.json({
            success: true,
            userId,
            forecast,
        });
    } catch (err) {
        console.error('❌ Forecast error:', err.message);
        res.status(err.statusCode || 500).json({ success: false, error: err.message });
    }
});

// ============================================================
// POST /api/intervene/:userId
// Full pipeline: Forecast → Claude Agent → Stripe Executor
// ============================================================
app.post('/api/intervene/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(`\n🚨 [POST /api/intervene/${userId}] Full intervention pipeline starting...`);

    try {
        // Step 1: Load data & run forecast
        const { userData, transactions } = await loadUserData(userId);
        const forecast = runForecast(userData, transactions);

        console.log(`   Step 1 ✅ Forecast complete. Risk: ${forecast.isAtRiskOfDefault}`);

        // Step 2: Guard — only intervene if user is actually at risk
        // (For hackathon demo we run the agent regardless to show the full pipeline)
        // if (!forecast.isAtRiskOfDefault) {
        //   return res.json({ success: true, message: 'No intervention needed.', forecast });
        // }

        // Step 3: Run Claude Haiku agent
        const agentPlan = await runAgentAnalysis(forecast);
        console.log(`   Step 2 ✅ Agent analysis complete. Actions: ${agentPlan.agent_actions?.length || 0}`);

        // Step 4: Execute the agent's plan (Stripe cancellations, etc.)
        const executionSummary = await executeAgentPlan(agentPlan);
        console.log('   Step 3 ✅ Execution complete.');

        res.json({
            success: true,
            userId,
            pipeline: {
                step1_forecast: forecast,
                step2_agent_plan: agentPlan,
                step3_execution_summary: executionSummary,
            },
        });
    } catch (err) {
        console.error('❌ Intervention pipeline error:', err.message);
        res.status(err.statusCode || 500).json({ success: false, error: err.message });
    }
});

// ============================================================
// Serve index.html for root (catch-all for SPA)
// ============================================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// Start Server
// ============================================================
app.listen(PORT, () => {
    console.log(`\n🚀 Agentic Early Warning System running on http://localhost:${PORT}`);
    console.log(`   Forecast endpoint : GET  http://localhost:${PORT}/api/forecast/user_123`);
    console.log(`   Intervene endpoint: POST http://localhost:${PORT}/api/intervene/user_123\n`);
});
