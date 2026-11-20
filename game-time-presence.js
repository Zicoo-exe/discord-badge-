(async () => {
    "use strict";

    if (typeof webpackChunkdiscord_app === "undefined") {
        console.error("[Game Time] Discord desktop client required.");
        return;
    }

    const INSTANCE_KEY = "__gameTimePresence";
    const previous = window[INSTANCE_KEY];
    if (previous?.stop) {
        console.warn("[Game Time] Replacing the previous instance.");
        try { previous.stop(); } catch (_) {}
    }
    window[INSTANCE_KEY] = { loading: true };

    const CONFIG = Object.freeze({
        totalHours: 6000,
        games: 250,
        batchSize: 25,
        delayMs: 450,
        wobble: false,
        dryRun: false
    });

    const CATALOG_URL = "https://cdn.discordapp.com/detectables/games.json";

    // ── helpers ──────────────────────────────────────────────────────────────
    const uuid = () => crypto.randomUUID();
    const sha256 = async value => new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
    );
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
    const b64utf8 = value => {
        const bytes = new TextEncoder().encode(value);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    };

    // ── webpack ───────────────────────────────────────────────────────────────
    function getWebpackRequire() {
        // Prefer Vencord's already-extracted require
        if (window.Vencord?.Webpack?.wreq?.c) return window.Vencord.Webpack.wreq;

        let best = null;
        try {
            webpackChunkdiscord_app.push([[Symbol("gtp")], {}, r => {
                if (!best || Object.keys(r?.c ?? {}).length > Object.keys(best?.c ?? {}).length)
                    best = r;
            }]);
            webpackChunkdiscord_app.pop();
        } catch (_) {}
        return best;
    }

    function allExports(req) {
        return Object.values(req?.c ?? {}).flatMap(mod => {
            try {
                const exp = mod?.exports;
                if (!exp) return [];
                return [exp, exp.default, ...(typeof exp === "object" ? Object.values(exp) : [])];
            } catch (_) { return []; }
        }).filter(Boolean);
    }

    const HTTP_METHODS = ["get", "post", "del"];
    const isHttpClient = c => c != null && HTTP_METHODS.every(m => typeof c[m] === "function");

    function findHttpClient(req) {
        // 1. try cache first (fastest)
        for (const mod of Object.values(req?.c ?? {})) {
            try {
                const client = [mod?.exports, mod?.exports?.default, ...Object.values(mod?.exports ?? {})]
                    .find(isHttpClient);
                if (client) return client;
            } catch (_) {}
        }
        // 2. scan module factory sources for HTTPUtils
        for (const [id, factory] of Object.entries(req?.m ?? {})) {
            let src = "";
            try { src = typeof factory === "function" ? factory.toString() : ""; } catch (_) {}
            if (!src.includes("HTTPUtils") && !src.includes("http-utils") && !src.includes("DiscordNative")) continue;
            try {
                const client = allExports(req).find(isHttpClient); // already computed but fast
                if (client) return client;
                // force-require the specific module
                const exp = req(id);
                const c2 = [exp, exp?.default, ...Object.values(exp ?? {})].find(isHttpClient);
                if (c2) return c2;
            } catch (_) {}
        }
        return null;
    }

    // ── super-properties ─────────────────────────────────────────────────────
    function readClientMeta(req) {
        // Try to pull live values from Discord's own BuildInfo module
        for (const mod of Object.values(req?.c ?? {})) {
            try {
                const exp = mod?.exports ?? {};
                const vals = [exp, exp.default, ...Object.values(exp)];
                for (const v of vals) {
                    if (v?.versionHash && v?.releaseChannel && v?.number) {
                        return {
                            version: String(v.versionString ?? v.version ?? "1.0.9253"),
                            buildNumber: Number(v.number ?? 594031),
                            nativeBuildNumber: Number(v.nativeVersion ?? 88414),
                            releaseChannel: String(v.releaseChannel ?? "stable")
                        };
                    }
                }
            } catch (_) {}
        }
        // sensible fallback — works until Discord ships a breaking schema change
        return { version: "1.0.9253", buildNumber: 594031, nativeBuildNumber: 88414, releaseChannel: "stable" };
    }

    function buildSuperProps(meta, launchSig, heartbeatSid, clientLaunchId) {
        return b64utf8(JSON.stringify({
            os: "Windows",
            browser: "Discord Client",
            release_channel: meta.releaseChannel,
            client_version: meta.version,
            os_version: "10.0.26200",
            os_arch: "x64",
            app_arch: "x64",
            system_locale: "en-US",
            has_client_mods: false,
            browser_user_agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/${meta.version} Chrome/148.0.7778.280 Electron/42.7.1 Safari/537.36`,
            browser_version: "42.7.1",
            os_sdk_version: "26200",
            client_build_number: meta.buildNumber,
            native_build_number: meta.nativeBuildNumber,
            client_event_source: null,
            client_app_state: "focused",
            client_launch_id: clientLaunchId,
            launch_signature: launchSig,
            client_heartbeat_session_id: heartbeatSid
        }));
    }

    // ── fingerprint ───────────────────────────────────────────────────────────
    const MACHINE_GUID = (() => {
        // Persist across runs so fingerprint stays stable per browser profile
        const KEY = "__gtpMachineGuid";
        try {
            let g = localStorage.getItem(KEY);
            if (!g) { g = uuid(); localStorage.setItem(KEY, g); }
            return g;
        } catch (_) { return uuid(); }
    })();

    async function fingerprintFor(userId) {
        const binary = new Uint8Array(146);
        const view = new DataView(binary.buffer);
        binary[0] = 1; binary[1] = 3;
        view.setUint32(2, 45829120, true);
        view.setUint32(6, 0, true);
        view.setUint32(10, 1700000000, true);
        view.setUint32(14, 50000000, true);
        binary.set(await sha256("pe_header_" + userId), 18);
        binary.set(await sha256(MACHINE_GUID + userId), 50);
        binary.set(await sha256("pe_section_" + userId), 82);
        binary.set(await sha256("pe_cert_" + userId), 114);
        const mask = await sha256(userId + "https://discord.com/careers");
        for (let i = 1; i < binary.length; i++) binary[i] ^= mask[(i - 1) & 31];
        let str = "";
        for (let i = 0; i < binary.length; i++) str += String.fromCharCode(binary[i]);
        return btoa(str);
    }

    // ── catalog ───────────────────────────────────────────────────────────────
    function normalizeGame(app) {
        if (app?.id == null) return null;
        const winExe = app?.executables?.find(e => e?.os === "win32" && e?.name);
        const exeName = winExe
            ? winExe.name.replace(/^>/, "")
            : (!app.executables || app.executables.length === 0)
                ? `${(app.name || "game").replace(/[^a-zA-Z0-9]/g, "").toLowerCase() || "game"}.exe`
                : null;
        if (!exeName) return null;
        return { id: String(app.id), name: app?.name ?? "Unknown", exe: exeName };
    }

    function shuffle(items) {
        for (let i = items.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [items[i], items[j]] = [items[j], items[i]];
        }
        return items;
    }

    async function getCatalog(client) {
        let apps = null;
        // Try internal API first
        try {
            const res = await client?.get({ url: "/applications/detectable" });
            const payload = res?.body;
            apps = Array.isArray(payload) ? payload : payload?.applications;
        } catch (_) {}
        // Fall back to public CDN
        if (!Array.isArray(apps)) {
            try {
                const res = await fetch(CATALOG_URL, { cache: "no-store" });
                if (res.ok) apps = await res.json();
            } catch (_) {}
        }
        if (!Array.isArray(apps)) throw new Error("The detectable-game catalog is unavailable.");
        const unique = new Map();
        for (const app of apps) {
            const game = normalizeGame(app);
            if (game && !unique.has(game.id)) unique.set(game.id, game);
        }
        if (unique.size === 0) throw new Error("No detectable games were found.");
        return [...unique.values()];
    }

    // ── auth ──────────────────────────────────────────────────────────────────
    function extractToken(req) {
        const exports = allExports(req);
        // Try AuthenticationStore
        for (const v of exports) {
            try {
                if (v && typeof v.getToken === "function" &&
                    (v.getName?.() === "AuthenticationStore" || v.__proto__?.constructor?.displayName === "AuthenticationStore")) {
                    const t = v.getToken();
                    if (t && typeof t === "string") return t;
                }
            } catch (_) {}
        }
        // Fallback: any export with getToken()
        for (const v of exports) {
            try {
                if (v && typeof v.getToken === "function") {
                    const t = v.getToken();
                    if (t && typeof t === "string" && t.length > 20) return t;
                }
            } catch (_) {}
        }
        return null;
    }

    async function getAuthContext(req, superProps) {
        const token = extractToken(req);
        if (!token) throw new Error("Discord token could not be found.");

        const response = await fetch("https://discord.com/api/v9/users/@me?with_analytics_token=true", {
            headers: {
                "authorization": token,
                "x-super-properties": superProps
            }
        });
        if (!response.ok) throw new Error(`/users/@me returned ${response.status}`);
        const profile = await response.json();

        const analyticsToken = profile.analytics_token;
        const userId = profile.id == null ? "" : String(profile.id);
        const username = profile.username || "user";
        if (!analyticsToken) throw new Error("analytics_token is missing from this session.");
        if (!/^\d+$/.test(userId)) throw new Error("Discord user ID could not be resolved.");
        return {
            analyticsToken,
            username,
            fingerprint: await fingerprintFor(userId),
            superProps,
            token
        };
    }

    // ── events ────────────────────────────────────────────────────────────────
    const STAGGER_MINUTES = 25;

    function sessionEvents(game, baseMs, context, state, gameIndex = 0) {
        const drift = CONFIG.wobble ? 1 + (Math.random() * 0.06 - 0.03) : 1;
        const durationMs = Math.max(360000, Math.round(baseMs * drift));
        const sessionId = uuid();
        const offsetMs = gameIndex * (STAGGER_MINUTES * 60 * 1000);
        const now = Date.now() - offsetMs;
        const start = Math.max(0, now - durationMs);
        const jitter = Math.floor(Math.random() * 450) + 120;

        const launch = {
            client_track_timestamp: start + jitter,
            client_heartbeat_session_id: state.heartbeat,
            game: game.name,
            game_id: game.id,
            verified: true,
            elevated: false,
            is_launcher: false,
            game_platform: "desktop",
            detection_method: "verified_game",
            is_overlay_enabled: false,
            is_overlay_game_enabled: true,
            is_overlay_game_source: "OOP_DEFAULT_DATABASE",
            fullscreen_type: "UNKNOWN",
            hardware_display_count: 1,
            overlay_method: "Disabled",
            activity_status_enabled: true,
            activity_status_shared_guilds: [],
            current_user_status: "online",
            game_detection_enabled: true,
            executable_path: game.exe,
            voice_channel_id: null,
            voice_channel_type: null,
            voice_channel_bitrate: null,
            voice_channel_guild_id: null,
            hidden_by_distributor: false,
            game_metadata: null,
            executable_fingerprint: context.fingerprint,
            client_performance_cpu: null,
            client_performance_memory: null,
            cpu_core_count: null,
            accessibility_features: 0,
            rendered_locale: "en-US",
            launch_signature: state.signature,
            client_rtc_state: null,
            client_app_state: "focused",
            client_send_timestamp: start + jitter
        };

        const events = [
            {
                type: "running_game_heartbeat",
                properties: {
                    client_track_timestamp: start,
                    client_heartbeat_session_id: state.heartbeat,
                    game_id: game.id,
                    game_name: game.name,
                    game_metadata: null,
                    game_executable: game.exe,
                    game_detection_enabled: true,
                    initial_heartbeat: true,
                    final_heartbeat: false,
                    game_session_id: sessionId,
                    duration_tracked_ms: 0,
                    rtc_connection_id: null,
                    media_session_id: null,
                    launch_signature: state.signature,
                    client_app_state: "focused",
                    client_send_timestamp: start
                }
            },
            { type: "launch_game", properties: launch },
            {
                type: "running_game_heartbeat",
                properties: {
                    client_track_timestamp: now,
                    client_heartbeat_session_id: state.heartbeat,
                    game_id: game.id,
                    game_name: game.name,
                    game_metadata: null,
                    game_executable: game.exe,
                    game_detection_enabled: true,
                    initial_heartbeat: false,
                    final_heartbeat: true,
                    game_session_id: sessionId,
                    duration_tracked_ms: durationMs,
                    rtc_connection_id: null,
                    media_session_id: null,
                    launch_signature: state.signature,
                    client_app_state: "focused",
                    client_send_timestamp: now
                }
            }
        ];

        for (const event of events) {
            event.properties.event_sequence_number = ++state.sequence;
        }
        return { events, hours: durationMs / 3600000 };
    }

    // ── send ──────────────────────────────────────────────────────────────────
    async function sendBatch(events, context, retry = 0) {
        if (CONFIG.dryRun) return true;
        try {
            const response = await fetch("https://discord.com/api/v9/science", {
                method: "POST",
                headers: {
                    "accept": "*/*",
                    "accept-language": "en-US",
                    "authorization": context.token,
                    "content-type": "application/json",
                    "origin": "https://discord.com",
                    "referer": "https://discord.com/channels/@me",
                    "x-super-properties": context.superProps
                },
                body: JSON.stringify({ token: context.analyticsToken, events })
            });
            if (response.status === 200 || response.status === 204) return true;
            if (response.status === 429) {
                const retryAfter = response.headers.get("retry-after");
                const cooldown = retryAfter ? parseFloat(retryAfter) * 1000 : 5000;
                console.warn(`[Game Time] Rate limited (429). Waiting ${(cooldown / 1000).toFixed(1)}s...`);
                await wait(cooldown);
                if (retry < 3) return sendBatch(events, context, retry + 1);
            }
            const text = await response.text().catch(() => "");
            console.warn(`[Game Time] Science returned ${response.status}` + (text ? `: ${text.slice(0, 200)}` : ""));
            return false;
        } catch (error) {
            if (retry < 2) {
                await wait(1500);
                return sendBatch(events, context, retry + 1);
            }
            return false;
        }
    }

    // ── main ──────────────────────────────────────────────────────────────────
    const state = {
        heartbeat: uuid(),
        signature: uuid(),
        sequence: 0
    };

    let credited = 0;
    let running = false;
    let stopped = false;

    async function boost(totalHours = CONFIG.totalHours, gameCount = CONFIG.games) {
        if (stopped) return 0;
        if (running) { console.warn("[Game Time] A boost is already running."); return 0; }
        if (!Number.isFinite(totalHours) || totalHours <= 0) {
            console.warn("[Game Time] Invalid hour target."); return 0;
        }
        running = true;
        try {
            const req = getWebpackRequire();
            if (!req?.c) throw new Error("Discord's webpack registry was not found.");
            const client = findHttpClient(req);
            if (!client) throw new Error("Discord's internal HTTP client could not be located.");

            const meta = readClientMeta(req);
            const launchSig = uuid();
            const heartbeatSid = uuid();
            const clientLaunchId = uuid();
            const superProps = buildSuperProps(meta, launchSig, heartbeatSid, clientLaunchId);

            console.log("[Game Time] Loading the detectable-game catalog...");
            const catalog = shuffle(await getCatalog(client));
            const selected = catalog.slice(0, Math.min(gameCount, catalog.length));
            const hoursPerGame = totalHours / selected.length;
            const baseDurationMs = Math.round(hoursPerGame * 3600 * 1000);

            const context = { ...(await getAuthContext(req, superProps)) };
            console.log(`[Game Time] Connected as ${context.username} | target: ${totalHours}h across ${selected.length} games (~${hoursPerGame.toFixed(1)}h/game) | build ${meta.buildNumber}`);
            if (CONFIG.dryRun) console.warn("[Game Time] Dry-run mode is ON — no data will be sent.");
            if (stopped) return 0;

            let forgedCount = 0;
            const totalBatches = Math.ceil(selected.length / CONFIG.batchSize);

            for (let offset = 0; offset < selected.length; offset += CONFIG.batchSize) {
                if (stopped) break;
                const chunk = selected.slice(offset, offset + CONFIG.batchSize);
                const allEvents = [];
                let chunkHours = 0;

                for (let i = 0; i < chunk.length; i++) {
                    const result = sessionEvents(chunk[i], baseDurationMs, context, state, offset + i);
                    allEvents.push(...result.events);
                    chunkHours += result.hours;
                }

                const batchNum = Math.floor(offset / CONFIG.batchSize) + 1;
                const accepted = await sendBatch(allEvents, context);

                if (accepted) {
                    forgedCount += chunk.length;
                    credited += chunkHours;
                    const tag = CONFIG.dryRun ? "[dry-run] " : "";
                    console.log(`[Game Time] ${tag}Batch ${batchNum}/${totalBatches} accepted (+${chunkHours.toFixed(1)}h, total ${credited.toFixed(0)}h)`);
                } else {
                    console.warn(`[Game Time] Batch ${batchNum}/${totalBatches} was rejected.`);
                }

                if (offset + CONFIG.batchSize < selected.length && !stopped) {
                    const jitter = CONFIG.delayMs + Math.floor((Math.random() - 0.5) * 150);
                    await wait(Math.max(100, jitter));
                }
            }

            if (credited > 0) {
                console.log(`[Game Time] Done: ${forgedCount}/${selected.length} games | ${credited.toFixed(0)}h accepted. Badge updates may take 24-48h.`);
            }
            return credited;
        } finally {
            running = false;
        }
    }

    function stop() {
        if (stopped) return;
        stopped = true;
        delete window[INSTANCE_KEY];
        console.log("[Game Time] Stopped.");
    }

    window[INSTANCE_KEY] = { boost, stop, get creditedHours() { return credited; } };
    window.addEventListener("pagehide", stop, { once: true });

    console.log("[Game Time] Ready. Auto-boost starting...");
    console.log(`[Game Time] Manual: await window.__gameTimePresence.boost(${CONFIG.totalHours}, ${CONFIG.games})`);
    console.log("[Game Time] Stop:   window.__gameTimePresence.stop()");

    setTimeout(() => {
        boost(CONFIG.totalHours, CONFIG.games).catch(err =>
            console.warn(`[Game Time] Boost failed: ${err.message}`)
        );
    }, 1200);
})();
