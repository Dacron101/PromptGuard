/**
 * utils/predictor.js
 * The "Quant" Forecasting Engine.
 *
 * Analyzes a user's Firestore transaction history and calculates a forward-looking
 * cash position to determine overdraft risk before the next payday.
 */

/**
 * @typedef {Object} ForecastResult
 * @property {boolean} isAtRiskOfDefault - True if projected balance goes negative.
 * @property {number} forecastedBalance - Projected balance on payday.
 * @property {number} forecastedShortfall - Negative indicates a deficit.
 * @property {number} daysUntilPayday - Calendar days remaining.
 * @property {number} avgDailyVariableSpend - Calculated average.
 * @property {number} totalUpcomingFixed - Fixed bills still owed before payday.
 * @property {Object} spendBreakdown - Categorized spending data.
 */

/**
 * Runs the predictive quant model against the user's transaction history.
 *
 * @param {Object} userData - User document from Firestore.
 * @param {Array}  transactions - Array of transaction documents.
 * @returns {ForecastResult}
 */
function runForecast(userData, transactions) {
    const { balance, current_date, next_payday } = userData;

    // --- Date Setup ---
    const today = new Date(current_date);
    const payday = new Date(next_payday);
    const daysUntilPayday = Math.ceil((payday - today) / (1000 * 60 * 60 * 24));
    const thirtyDaysAgo = new Date(today);
    thirtyDaysAgo.setDate(today.getDate() - 30);

    // --- Categorize Transactions ---
    const spendBreakdown = {
        subscriptions: [],
        fixedBills: [],
        variableSpend: [],
        income: [],
    };

    transactions.forEach((tx) => {
        const txDate = new Date(tx.date);
        switch (tx.category) {
            case 'income':
                spendBreakdown.income.push(tx);
                break;
            case 'subscription':
                spendBreakdown.subscriptions.push(tx);
                break;
            case 'fixed_bill':
                // Only count bills that haven't been paid yet (next_due is before payday)
                if (tx.next_due) {
                    const dueDate = new Date(tx.next_due);
                    if (dueDate >= today && dueDate <= payday) {
                        spendBreakdown.fixedBills.push(tx);
                    }
                }
                break;
            case 'variable':
                // Only count variable spend in the last 30 days for baseline calculation
                if (txDate >= thirtyDaysAgo && txDate <= today) {
                    spendBreakdown.variableSpend.push(tx);
                }
                break;
        }
    });

    // --- Upcoming Subscriptions (due before payday) ---
    const upcomingSubscriptions = spendBreakdown.subscriptions.filter((tx) => {
        if (!tx.next_due) return false;
        const dueDate = new Date(tx.next_due);
        return dueDate >= today && dueDate <= payday;
    });

    // --- CALCULATION 1: Total upcoming fixed obligations ---
    const totalUpcomingFixed =
        spendBreakdown.fixedBills.reduce((sum, tx) => sum + Math.abs(tx.amount), 0) +
        upcomingSubscriptions.reduce((sum, tx) => sum + Math.abs(tx.amount), 0);

    // --- CALCULATION 2: Average daily variable spend (last 30 days) ---
    const totalVariableSpend30d = spendBreakdown.variableSpend.reduce(
        (sum, tx) => sum + Math.abs(tx.amount),
        0
    );
    const avgDailyVariableSpend = totalVariableSpend30d / 30;

    // --- CALCULATION 3: Forecast Formula ---
    // Projected Balance = Current Balance - Upcoming Fixed - (Avg Daily Spend * Days Until Payday)
    const projectedVariableTotal = avgDailyVariableSpend * daysUntilPayday;
    const forecastedBalance = balance - totalUpcomingFixed - projectedVariableTotal;
    const forecastedShortfall = forecastedBalance; // Negative = shortfall
    const isAtRiskOfDefault = forecastedBalance < 0;

    return {
        isAtRiskOfDefault,
        forecastedBalance: parseFloat(forecastedBalance.toFixed(2)),
        forecastedShortfall: parseFloat(forecastedShortfall.toFixed(2)),
        currentBalance: balance,
        daysUntilPayday,
        avgDailyVariableSpend: parseFloat(avgDailyVariableSpend.toFixed(2)),
        totalUpcomingFixed: parseFloat(totalUpcomingFixed.toFixed(2)),
        projectedVariableTotal: parseFloat(projectedVariableTotal.toFixed(2)),
        spendBreakdown: {
            totalVariable30d: parseFloat(totalVariableSpend30d.toFixed(2)),
            upcomingFixedBills: spendBreakdown.fixedBills.map((tx) => ({
                description: tx.description,
                amount: Math.abs(tx.amount),
                due: tx.next_due,
            })),
            upcomingSubscriptions: upcomingSubscriptions.map((tx) => ({
                description: tx.description,
                amount: Math.abs(tx.amount),
                due: tx.next_due,
                stripe_sub_id: tx.stripe_sub_id,
            })),
            topVariableCategories: getTopCategories(spendBreakdown.variableSpend),
        },
        next_payday,
        current_date,
    };
}

/**
 * Groups variable transactions by description prefix and returns top spenders.
 * @param {Array} variableTxs
 * @returns {Array}
 */
function getTopCategories(variableTxs) {
    const groups = {};
    variableTxs.forEach((tx) => {
        // Normalize: "Starbucks Coffee" -> "Coffee/Cafes", "Whole Foods" -> "Groceries", etc.
        const key = classifyVariable(tx.description);
        if (!groups[key]) groups[key] = 0;
        groups[key] += Math.abs(tx.amount);
    });

    return Object.entries(groups)
        .map(([category, total]) => ({ category, total: parseFloat(total.toFixed(2)) }))
        .sort((a, b) => b.total - a.total);
}

function classifyVariable(description) {
    const lower = description.toLowerCase();
    if (lower.includes('coffee') || lower.includes('cafe') || lower.includes('starbucks') || lower.includes('blue bottle')) return 'Coffee/Cafes';
    if (lower.includes('whole foods') || lower.includes('trader') || lower.includes('safeway') || lower.includes('grocery')) return 'Groceries';
    if (lower.includes('uber eats') || lower.includes('doordash') || lower.includes('restaurant')) return 'Dining/Delivery';
    if (lower.includes('amazon') || lower.includes('target')) return 'Shopping';
    return 'Other';
}

module.exports = { runForecast };
