/**
 * utils/agent.js
 * Claude 3 Haiku Agentic Financial Intervention Engine.
 *
 * Takes the output of the forecasting engine, builds a structured prompt,
 * and asks Claude to analyze the risk and recommend specific interventions.
 * Claude is prompted to output ONLY strict JSON.
 */

require('dotenv').config();
const Anthropic = require('@anthropic-ai/sdk');

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// --- System Prompt ---
const SYSTEM_PROMPT = `You are a ruthless financial intervention agent embedded in a banking app.
The user is at serious risk of defaulting/overdrafting before their next payday.
Your job is to analyze their spending data and issue harsh, actionable directives.

RULES:
1. Identify the biggest offenders in their variable and subscription spending.
2. If there is any way to avoid the default by canceling a subscription, include it in agent_actions.
3. Be direct, specific, and unsentimental. This is about financial survival.
4. You MUST output ONLY a single valid JSON object — no markdown, no explanation, no preamble.

OUTPUT SCHEMA (strict JSON only):
{
  "risk_assessment": "string — 1-2 sentence blunt summary of why they will default",
  "budget_advice": ["array of strings — specific cuts with dollar amounts where possible"],
  "agent_actions": [
    {
      "intent": "CANCEL_SUBSCRIPTION",
      "target_service": "string — name of the subscription service",
      "stripe_subscription_id": "string — the subscription id",
      "saved_amount": number,
      "rationale": "string — one-line reason for this specific cut"
    }
  ]
}

If no subscription cancellation is needed, return an empty array for agent_actions.
Do NOT wrap the JSON in markdown code fences. Output raw JSON only.`;

/**
 * Runs the Claude 3 Haiku agent with the forecast data as context.
 *
 * @param {Object} forecastData - Result from predictor.runForecast()
 * @returns {Promise<Object>} Parsed JSON response from Claude
 */
async function runAgentAnalysis(forecastData) {
    console.log('\n🤖 Invoking Claude 3 Haiku agent...');

    // Build a rich user message from the forecast data
    const userMessage = buildUserMessage(forecastData);

    const response = await client.messages.create({
        model: 'claude-3-haiku-20240307',
        max_tokens: 1024,
        system: SYSTEM_PROMPT,
        messages: [
            {
                role: 'user',
                content: userMessage,
            },
        ],
    });

    const rawText = response.content[0].text.trim();
    console.log('\n📨 Raw Claude response:');
    console.log(rawText);

    // --- Strict JSON Parsing ---
    let parsed;
    try {
        // Strip any accidental markdown fences (safety net)
        const cleaned = rawText.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
        parsed = JSON.parse(cleaned);
    } catch (err) {
        console.error('❌ Failed to parse Claude response as JSON:', err.message);
        throw new Error(`Claude returned invalid JSON: ${rawText}`);
    }

    return parsed;
}

/**
 * Builds the user message for Claude from structured forecast data.
 * @param {Object} forecast
 * @returns {string}
 */
function buildUserMessage(forecast) {
    const {
        currentBalance,
        forecastedBalance,
        forecastedShortfall,
        daysUntilPayday,
        avgDailyVariableSpend,
        totalUpcomingFixed,
        projectedVariableTotal,
        spendBreakdown,
        current_date,
        next_payday,
    } = forecast;

    const { upcomingFixedBills, upcomingSubscriptions, topVariableCategories } = spendBreakdown;

    return `
FINANCIAL SITUATION REPORT — ${current_date}

=== CASH POSITION ===
Current Balance: $${currentBalance}
Days Until Payday (${next_payday}): ${daysUntilPayday} days
Forecasted Balance on Payday: $${forecastedBalance}
SHORTFALL: $${Math.abs(forecastedShortfall)} ${forecastedShortfall < 0 ? '(DEFICIT — WILL DEFAULT)' : '(SAFE)'}

=== UPCOMING FIXED OBLIGATIONS ===
Total Fixed + Subscription Costs Before Payday: $${totalUpcomingFixed}
${upcomingFixedBills.map((b) => `  - ${b.description}: $${b.amount} due ${b.due}`).join('\n')}
${upcomingSubscriptions.map((s) => `  - ${s.description} (SUBSCRIPTION): $${s.amount} due ${s.due} | stripe_id: ${s.stripe_sub_id}`).join('\n')}

=== VARIABLE SPENDING (last 30 days) ===
Average Daily Spend: $${avgDailyVariableSpend}
Projected Variable Cost for ${daysUntilPayday} days: $${projectedVariableTotal}

Top Spending Categories:
${topVariableCategories.map((c) => `  - ${c.category}: $${c.total} (30-day total)`).join('\n')}

=== INTERVENTION REQUIRED ===
The user WILL overdraft if no action is taken. Analyze the subscriptions and variable spend above.
Identify which subscription(s) to cancel and provide concrete budget reduction targets.
Return ONLY the JSON response per your schema.
`.trim();
}

module.exports = { runAgentAnalysis };
