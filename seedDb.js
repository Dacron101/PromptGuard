/**
 * seedDb.js
 * Populates Firestore with a dummy user and transaction history for testing.
 * Run with: npm run seed
 */

require('dotenv').config();
const admin = require('firebase-admin');

// --- Firebase Initialization ---
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        // Replace literal \n in env var with actual newlines
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
});

const db = admin.firestore();

// --- Seed Data ---
const USER_ID = 'user_123';

const userData = {
    balance: 850,
    current_date: '2024-10-20',
    next_payday: '2024-11-01',
    name: 'Demo User',
    email: 'demo@hackathon.dev',
};

/**
 * Generates a date string N days before the reference date (2024-10-20).
 * @param {number} daysAgo
 * @returns {string} ISO date string
 */
function daysAgo(daysAgo) {
    const date = new Date('2024-10-20');
    date.setDate(date.getDate() - daysAgo);
    return date.toISOString().split('T')[0];
}

const transactions = [
    // ---- INCOME ----
    {
        description: 'Salary',
        amount: 3200.00,
        type: 'income',
        category: 'income',
        date: daysAgo(20),
        stripe_sub_id: null,
    },

    // ---- FIXED BILLS (upcoming / recent) ----
    {
        description: 'Rent',
        amount: -1200.00,
        type: 'expense',
        category: 'fixed_bill',
        date: daysAgo(18),
        // Rent due again before next payday
        next_due: '2024-11-01',
        stripe_sub_id: null,
    },
    {
        description: 'Electric Bill',
        amount: -95.00,
        type: 'expense',
        category: 'fixed_bill',
        date: daysAgo(15),
        next_due: '2024-10-28',
        stripe_sub_id: null,
    },

    // ---- SUBSCRIPTIONS ----
    {
        description: 'Netflix',
        amount: -15.99,
        type: 'expense',
        category: 'subscription',
        date: daysAgo(5),
        stripe_sub_id: 'sub_mock123',
        next_due: '2024-10-25',
    },
    {
        description: 'Spotify',
        amount: -9.99,
        type: 'expense',
        category: 'subscription',
        date: daysAgo(8),
        stripe_sub_id: 'sub_mock456',
        next_due: '2024-10-27',
    },
    {
        description: 'Gym Membership',
        amount: -45.00,
        type: 'expense',
        category: 'subscription',
        date: daysAgo(10),
        stripe_sub_id: 'sub_mock789',
        next_due: '2024-10-30',
    },

    // ---- VARIABLE SPEND (high burn rate) ----
    // Coffee
    { description: 'Starbucks Coffee', amount: -6.50, type: 'expense', category: 'variable', date: daysAgo(1) },
    { description: 'Blue Bottle Coffee', amount: -7.20, type: 'expense', category: 'variable', date: daysAgo(2) },
    { description: 'Starbucks Coffee', amount: -6.50, type: 'expense', category: 'variable', date: daysAgo(3) },
    { description: 'Local Cafe', amount: -5.80, type: 'expense', category: 'variable', date: daysAgo(4) },
    { description: 'Starbucks Coffee', amount: -6.50, type: 'expense', category: 'variable', date: daysAgo(6) },
    { description: 'Coffee Shop', amount: -7.00, type: 'expense', category: 'variable', date: daysAgo(7) },
    { description: 'Starbucks Coffee', amount: -6.50, type: 'expense', category: 'variable', date: daysAgo(9) },

    // Groceries
    { description: 'Whole Foods', amount: -87.50, type: 'expense', category: 'variable', date: daysAgo(3) },
    { description: 'Trader Joes', amount: -63.20, type: 'expense', category: 'variable', date: daysAgo(7) },
    { description: 'Whole Foods', amount: -92.10, type: 'expense', category: 'variable', date: daysAgo(12) },
    { description: 'Safeway', amount: -44.30, type: 'expense', category: 'variable', date: daysAgo(16) },

    // Dining out
    { description: 'Uber Eats', amount: -34.80, type: 'expense', category: 'variable', date: daysAgo(2) },
    { description: 'DoorDash', amount: -28.50, type: 'expense', category: 'variable', date: daysAgo(5) },
    { description: 'Restaurant', amount: -56.00, type: 'expense', category: 'variable', date: daysAgo(9) },
    { description: 'Uber Eats', amount: -22.30, type: 'expense', category: 'variable', date: daysAgo(11) },

    // Misc variable
    { description: 'Amazon', amount: -49.99, type: 'expense', category: 'variable', date: daysAgo(6) },
    { description: 'Target', amount: -38.75, type: 'expense', category: 'variable', date: daysAgo(13) },
];

// --- Seed Function ---
async function seedDatabase() {
    console.log('🌱 Starting database seed...\n');

    try {
        // 1. Write user document
        const userRef = db.collection('users').doc(USER_ID);
        await userRef.set(userData);
        console.log(`✅ Created user: ${USER_ID}`);
        console.log(`   Balance: $${userData.balance}`);
        console.log(`   Current Date: ${userData.current_date}`);
        console.log(`   Next Payday: ${userData.next_payday}\n`);

        // 2. Write transactions sub-collection (batch write for efficiency)
        const batch = db.batch();
        const txCollection = userRef.collection('transactions');

        transactions.forEach((tx) => {
            const txRef = txCollection.doc(); // auto-ID
            batch.set(txRef, { ...tx, created_at: admin.firestore.FieldValue.serverTimestamp() });
        });

        await batch.commit();
        console.log(`✅ Created ${transactions.length} transactions in sub-collection\n`);
        console.log('📊 Transaction breakdown:');
        console.log(`   Income:        ${transactions.filter(t => t.type === 'income').length} transactions`);
        console.log(`   Fixed Bills:   ${transactions.filter(t => t.category === 'fixed_bill').length} transactions`);
        console.log(`   Subscriptions: ${transactions.filter(t => t.category === 'subscription').length} transactions`);
        console.log(`   Variable:      ${transactions.filter(t => t.category === 'variable').length} transactions`);
        console.log('\n🎉 Database seeded successfully! Ready for testing.');

    } catch (error) {
        console.error('❌ Seed failed:', error);
        process.exit(1);
    } finally {
        process.exit(0);
    }
}

seedDatabase();
