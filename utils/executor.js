/**
 * utils/executor.js
 * Action Executor — parses Claude's agent plan and executes real-world interventions.
 *
 * Currently supports:
 *   - CANCEL_SUBSCRIPTION: calls Stripe to set cancel_at_period_end = true
 */

require('dotenv').config();
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
    apiVersion: '2023-10-16',
});

/**
 * Supported action intent handlers.
 */
const ACTION_HANDLERS = {
    CANCEL_SUBSCRIPTION: executeSubscriptionCancellation,
};

/**
 * Main executor entry point.
 * Iterates over Claude's `agent_actions` and dispatches each to the correct handler.
 *
 * @param {Object} agentPlan - Parsed JSON from Claude (output of agent.js)
 * @returns {Promise<Object>} Summary of executed and skipped actions
 */
async function executeAgentPlan(agentPlan) {
    const { agent_actions = [], risk_assessment, budget_advice } = agentPlan;

    console.log('\n⚡ Executor: processing agent plan...');
    console.log(`   → ${agent_actions.length} action(s) queued`);

    const executedActions = [];
    const skippedActions = [];

    for (const action of agent_actions) {
        const { intent } = action;
        const handler = ACTION_HANDLERS[intent];

        if (!handler) {
            console.warn(`⚠️  Unknown intent "${intent}" — skipping.`);
            skippedActions.push({ ...action, status: 'SKIPPED', reason: 'No handler registered' });
            continue;
        }

        try {
            const result = await handler(action);
            executedActions.push({ ...action, status: 'EXECUTED', result });
        } catch (error) {
            console.error(`❌ Action "${intent}" failed:`, error.message);
            executedActions.push({ ...action, status: 'FAILED', error: error.message });
        }
    }

    const summary = {
        risk_assessment,
        budget_advice,
        actions_executed: executedActions,
        actions_skipped: skippedActions,
        total_monthly_savings: executedActions
            .filter((a) => a.status === 'EXECUTED')
            .reduce((sum, a) => sum + (a.saved_amount || 0), 0),
    };

    console.log('\n✅ Execution complete. Summary:');
    console.log(JSON.stringify(summary, null, 2));

    return summary;
}

/**
 * Cancels a Stripe subscription by setting cancel_at_period_end = true.
 * This is the polite cancellation method — user keeps access until billing cycle ends.
 *
 * In test mode (STRIPE_SECRET_KEY=sk_test_...), this call safely returns a mock object.
 *
 * @param {Object} action - The agent_action object from Claude
 * @returns {Promise<Object>} Stripe subscription object or mock result
 */
async function executeSubscriptionCancellation(action) {
    const { target_service, stripe_subscription_id, saved_amount } = action;

    console.log(`\n🔪 Canceling subscription: ${target_service}`);
    console.log(`   Stripe Sub ID : ${stripe_subscription_id}`);
    console.log(`   Savings/month : $${saved_amount}`);

    // --- Detect mock IDs (for hackathon demo without real Stripe subs) ---
    if (stripe_subscription_id.startsWith('sub_mock')) {
        console.log('   Mode: MOCK — simulating Stripe API call (sub ID is a mock)');
        const mockResult = {
            id: stripe_subscription_id,
            object: 'subscription',
            cancel_at_period_end: true,
            status: 'active',
            metadata: { cancelled_by: 'agentic_early_warning_system' },
            _mock: true,
            _message: `[MOCK] Would have set cancel_at_period_end=true on ${stripe_subscription_id} for ${target_service}`,
        };
        console.log(`   ✅ MOCK cancellation recorded for ${target_service}`);
        return mockResult;
    }

    // --- Real Stripe API call ---
    const updatedSubscription = await stripe.subscriptions.update(stripe_subscription_id, {
        cancel_at_period_end: true,
        metadata: {
            cancelled_by: 'agentic_early_warning_system',
            reason: 'overdraft_prevention',
        },
    });

    console.log(`   ✅ Stripe confirmed: cancel_at_period_end=${updatedSubscription.cancel_at_period_end}`);
    console.log(`   Status: ${updatedSubscription.status}`);

    return {
        id: updatedSubscription.id,
        cancel_at_period_end: updatedSubscription.cancel_at_period_end,
        status: updatedSubscription.status,
        current_period_end: updatedSubscription.current_period_end,
    };
}

module.exports = { executeAgentPlan };
