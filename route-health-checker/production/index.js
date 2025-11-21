const axios = require("axios");

const MAX_LAST_ACTIVE_MS = 3 * 60 * 60 * 1000; // 3 hours

exports.dslRouteHealthCheck = async (req, res) => {
    try {
        const apiKey = process.env.TELERIVET_API_KEY;
        const projectId = process.env.TELERIVET_PROJECT_ID;

        if (!apiKey || !projectId) {
            console.error("❌ Missing required environment variables");
            return res.status(500).send("Server not configured");
        }

        const url = `https://api.telerivet.com/v1/projects/${projectId}/phones`;

        const response = await axios.get(url, {
            auth: {
                username: apiKey,
                password: ""
            }
        });

        const routes = response.data.data || [];

        console.log(`📡 Total routes found: ${routes.length}`);

        const now = Date.now();
        const unhealthyRoutes = [];

        for (const r of routes) {
            const issues = [];

            // Battery checks
            if (typeof r.battery === "number" && r.battery < 20) {
                issues.push(`Low battery (${r.battery}%)`);
            }

            if (typeof r.battery === "number" && r.battery < 30 && r.charging === false) {
                issues.push(`Battery low & not charging (${r.battery}%)`);
            }

            // Last active check
            if (r.last_active_time) {
                const lastActiveMs = r.last_active_time * 1000;
                if (now - lastActiveMs > MAX_LAST_ACTIVE_MS) {
                    const hours = ((now - lastActiveMs) / 3600000).toFixed(1);
                    issues.push(`Last active ${hours} hours ago`);
                }
            }

            // Internet connectivity
            if (!r.internet_type || r.internet_type === "NONE") {
                issues.push("No Internet connection");
            }

            // Sending paused
            if (r.send_paused === true) {
                issues.push("Sending paused");
            }

            if (issues.length > 0) {
                unhealthyRoutes.push({
                    id: r.id,
                    name: r.name,
                    phone_number: r.phone_number,
                    issues,
                    battery: r.battery,
                    charging: r.charging,
                    internet_type: r.internet_type,
                    last_active_time: r.last_active_time
                });
            }
        }

        if (unhealthyRoutes.length === 0) {
            console.log("✅ All routes are healthy");
        } else {
            console.warn("⚠️ Unhealthy routes detected:");
            console.warn(JSON.stringify(unhealthyRoutes, null, 2));
        }

        return res.status(200).json({
            status: "ok",
            total_routes: routes.length,
            unhealthy_count: unhealthyRoutes.length,
            unhealthy_routes: unhealthyRoutes
        });

    } catch (err) {
        console.error("❌ Error checking Telerivet routes:", err.response?.data || err.message);
        return res.status(500).send("Error fetching Telerivet routes");
    }
};
