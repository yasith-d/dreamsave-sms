require("dotenv").config();
const axios = require("axios");
const { WebClient } = require("@slack/web-api");

// Battery thresholds
const CRITICAL_BATTERY_THRESHOLD = 20;
const WARNING_BATTERY_THRESHOLD = 30;

// Initialize Slack client
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackChannel = process.env.SLACK_CHANNEL_ID;
const slackClient = new WebClient(slackToken);

async function testTelerivetRoutes() {
  try {
    const apiKey = process.env.TELERIVET_API_KEY;
    const projectId = process.env.TELERIVET_PROJECT_ID;

    if (!apiKey || !projectId) {
      console.error("Missing Telerivet environment variables");
      process.exit(1);
    }

    const url = `https://api.telerivet.com/v1/projects/${projectId}/phones`;
    console.log(`Calling Telerivet API: ${url}`);

    const response = await axios.get(url, {
      auth: { username: apiKey, password: "" }
    });

    const routes = response.data.data || [];
    console.log(`Total routes found: ${routes.length}`);

    const now = Date.now();
    const unhealthyRoutes = [];

    for (const r of routes) {
      const issues = [];

      // 1. Always flag if last_active_time is missing OR disconnected
      if (!r.last_active_time) {
        issues.push("Never reported active (disconnected)");
      } else {
        const lastActiveMs = r.last_active_time * 1000;
        const minutesAgo = ((now - lastActiveMs) / 60000).toFixed(1);
        issues.push(`Disconnected ${minutesAgo} minutes ago`);
      }

      // 2. Battery checks
      if (typeof r.battery === "number") {
        if (r.battery < CRITICAL_BATTERY_THRESHOLD) {
          issues.push(`Low battery (${r.battery}%)`);
        } else if (r.battery < WARNING_BATTERY_THRESHOLD && r.charging === false) {
          issues.push(`Battery low & not charging (${r.battery}%)`);
        }
      }

      // Add to unhealthy list if any issues
      if (issues.length > 0) {
        unhealthyRoutes.push({
          id: r.id,
          name: r.name,
          phone_number: r.phone_number,
          country: r.country,
          app_version: r.app_version,
          battery: r.battery,
          charging: r.charging,
          last_active_time: r.last_active_time,
          issues
        });
      }
    }

    console.log("\n====================================");
    console.log("ROUTE HEALTH SUMMARY");
    console.log("====================================");

    if (unhealthyRoutes.length === 0) {
      console.log("All routes are healthy.");
    } else {
      console.log(`Unhealthy routes: ${unhealthyRoutes.length}`);
      console.log(JSON.stringify(unhealthyRoutes, null, 2));

      // Send Slack message
      try {
        const messageText =
          `*DSL Route Health Check*\nUnhealthy routes detected:\n` +
          unhealthyRoutes
            .map(
              (r) =>
                `• ${r.name} (${r.phone_number}): ${r.issues.join(", ")}`
            )
            .join("\n");

        await slackClient.chat.postMessage({
          channel: slackChannel,
          text: messageText
        });

        console.log("Sent Slack notification for unhealthy routes.");
      } catch (slackErr) {
        console.error("Error sending Slack message:", slackErr.message);
      }
    }
  } catch (err) {
    console.error("Error calling Telerivet:", err.response?.data || err.message);
  }
}

// Run the test
testTelerivetRoutes();
