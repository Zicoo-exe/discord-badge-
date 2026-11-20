(async () => {
    "use strict";

    const LOCK = "__multiGamePresence";
    const GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json";
    const AUTO_CLAIM_HOURS = 2;
    const BATCH_SIZE = 100;
    const BATCH_DELAY_MS = 0;

    if (window[LOCK]) {
        try { window[LOCK].stop?.(); } catch (_) {}
        delete window[LOCK];
        await new Promise(r => setTimeout(r, 300));
    }
    window[LOCK] = { loading: true };

    const uuid = () => crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const isLinux = /Linux/i.test(navigator.userAgent);
    const b64utf8 = value => {
        const bytes = new TextEncoder().encode(value);
        let bin = "";
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    };
    const sha256 = async value => new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
    );
    const sleep = ms => new Promise(r => setTimeout(r, ms));

    const MACHINE_GUID = (() => {
        const KEY = "__mgpMachineGuid";
        try {
            let g = localStorage.getItem(KEY);
            if (!g) { g = uuid(); localStorage.setItem(KEY, g); }
            return g;
        } catch (_) { return uuid(); }
    })();

    function getWebpackRequire() {
        if (window.Vencord?.Webpack?.wreq?.c) return window.Vencord.Webpack.wreq;
        if (typeof webpackChunkdiscord_app === "undefined") return null;
        let best = null;
        try {
            webpackChunkdiscord_app.push([[Symbol("mgp")], {}, r => {
                if (!best || Object.keys(r?.c ?? {}).length > Object.keys(best?.c ?? {}).length)
                    best = r;
            }]);
            webpackChunkdiscord_app.pop();
        } catch (_) {}
        return best;
    }

    function collectExports(req) {
        return Object.values(req?.c ?? {}).flatMap(mod => {
            try {
                const exp = mod?.exports;
                if (!exp) return [];
                return [exp, exp.default, ...(typeof exp === "object" ? Object.values(exp) : [])];
            } catch (_) { return []; }
        }).filter(Boolean);
    }

    function findStore(exports, name) {
        const origWarn = console.warn;
        try {
            console.warn = () => {};
            return exports.find(v => {
                try {
                    return v && typeof v === "object" &&
                        (v.getName?.() === name || v.__proto__?.constructor?.displayName === name);
                } catch (_) { return false; }
            });
        } finally { console.warn = origWarn; }
    }

    function findDispatcher(exports) {
        const origWarn = console.warn;
        try {
            console.warn = () => {};
            return exports.find(v => v && typeof v.dispatch === "function" &&
                typeof v.subscribe === "function" && v._subscriptions);
        } finally { console.warn = origWarn; }
    }

    function readClientMeta(exports) {
        for (const v of exports) {
            try {
                if (v?.versionHash && v?.releaseChannel && v?.number) {
                    return {
                        version: String(v.versionString ?? v.version ?? "1.0.9253"),
                        buildNumber: Number(v.number ?? 594031),
                        nativeBuildNumber: Number(v.nativeVersion ?? 88414),
                        releaseChannel: String(v.releaseChannel ?? "stable")
                    };
                }
                if (v?.VERSION && v?.BUILD_NUMBER && typeof v.BUILD_NUMBER === "number") {
                    return {
                        version: String(v.VERSION),
                        buildNumber: Number(v.BUILD_NUMBER),
                        nativeBuildNumber: Number(v.NATIVE_BUILD_NUMBER ?? 88414),
                        releaseChannel: String(v.RELEASE_CHANNEL ?? "stable")
                    };
                }
            } catch (_) {}
        }
        return { version: "1.0.9253", buildNumber: 594031, nativeBuildNumber: 88414, releaseChannel: "stable" };
    }

    function buildSuperProps(meta, launchSignature, heartbeatSession, clientLaunchId) {
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
            launch_signature: launchSignature,
            client_heartbeat_session_id: heartbeatSession
        }));
    }

    async function generateFingerprint(userId) {
        const out = new Uint8Array(146);
        out[0] = 1; out[1] = 3;
        const view = new DataView(out.buffer);
        view.setUint32(2, 45829120, true);
        view.setUint32(6, 0, true);
        view.setUint32(10, 1700000000, true);
        view.setUint32(14, 50000000, true);
        out.set(await sha256("pe_header_" + userId), 18);
        out.set(await sha256(MACHINE_GUID + userId), 50);
        out.set(await sha256("pe_section_" + userId), 82);
        out.set(await sha256("pe_cert_" + userId), 114);
        const key = await sha256(userId + "https://discord.com/careers");
        for (let i = 1; i < out.length; i++) out[i] ^= key[(i - 1) & 31];
        let bin = "";
        for (let i = 0; i < out.length; i++) bin += String.fromCharCode(out[i]);
        return btoa(bin);
    }

    function parseGames(list) {
        const seen = new Set();
        const games = [];
        for (const raw of list ?? []) {
            const id = String(raw?.id ?? "");
            if (!/^\d+$/.test(id) || seen.has(id)) continue;
            const executables = Array.isArray(raw?.executables) ? raw.executables : [];
            const win = executables.find(e => e?.os === "win32" && e?.name);
            if (!win) continue;
            const linux = executables.find(e => e?.os === "linux" && e?.name);
            seen.add(id);
            games.push({
                name: String(raw?.name ?? "Unknown"),
                id,
                win_exe: String(win.name).replace(/>/g, ""),
                linux_exe: linux ? String(linux.name).replace(/>/g, "") : ""
            });
        }
        return games;
    }

    async function loadGames(detectableStore) {
        console.log("[MGP] Loading games...");
        try {
            const res = await fetch(GAMES_CDN_URL, { cache: "no-store" });
            if (!res.ok) throw new Error(`${res.status}`);
            const games = parseGames(await res.json());
            if (games.length) { console.log(`[MGP] ${games.length} games loaded.`); return games; }
        } catch (err) { console.warn(`[MGP] CDN failed: ${err.message}`); }
        try {
            const games = parseGames(detectableStore?.getDetectableGames?.() ?? []);
            if (games.length) return games;
        } catch (_) {}
        throw new Error("Could not load game list.");
    }

    function getToken(authStore, exports) {
        try { const t = authStore?.getToken?.(); if (t) return t; } catch (_) {}
        const origWarn = console.warn;
        try {
            console.warn = () => {};
            for (const exp of exports) {
                try {
                    if (exp && typeof exp.getToken === "function" && exp.getName?.() === "AuthenticationStore") {
                        const t = exp.getToken();
                        if (t) return t;
                    }
                } catch (_) {}
            }
        } finally { console.warn = origWarn; }
        return null;
    }

    function getUserId(token, authStore, userStore) {
        try {
            const uid = userStore?.getCurrentUser?.()?.id || authStore?.getId?.();
            if (uid && /^\d+$/.test(uid)) return String(uid);
        } catch (_) {}
        try {
            const part = String(token ?? "").split(".")[0];
            if (part && part !== "mfa") {
                const pad = "=".repeat((4 - (part.length % 4)) % 4);
                const decoded = atob(part + pad);
                if (/^\d+$/.test(decoded)) return decoded;
            }
        } catch (_) {}
        return "";
    }

    async function getAnalyticsToken(token, superProps) {
        try {
            const res = await fetch("https://discord.com/api/v9/users/@me?with_analytics_token=true", {
                headers: { "authorization": token, "x-super-properties": superProps }
            });
            if (!res.ok) return null;
            return (await res.json()).analytics_token ?? null;
        } catch (_) { return null; }
    }

    async function postScienceEvents(events, currentAuth, retry = 0) {
        try {
            const res = await fetch("https://discord.com/api/v9/science", {
                method: "POST",
                headers: {
                    "accept": "*/*",
                    "accept-language": "en-US",
                    "authorization": currentAuth.token,
                    "content-type": "application/json",
                    "origin": "https://discord.com",
                    "referer": "https://discord.com/channels/@me",
                    "x-super-properties": currentAuth.superProps
                },
                referrer: "https://discord.com/channels/@me",
                body: JSON.stringify({ token: currentAuth.analyticsToken, events })
            });
            if (res.status === 204 || res.status === 200) return true;
            if (res.status === 429 && retry < 4) {
                const wait = (parseFloat(res.headers.get("retry-after") ?? "3")) * 1000;
                console.warn(`[MGP] Rate limited, waiting ${(wait/1000).toFixed(1)}s...`);
                await sleep(Math.max(wait, 2000));
                return postScienceEvents(events, currentAuth, retry + 1);
            }
            console.warn(`[MGP] Science returned ${res.status}`);
            return false;
        } catch (err) {
            if (retry < 2) { await sleep(1500); return postScienceEvents(events, currentAuth, retry + 1); }
            throw err;
        }
    }

    let seq = 0;
    const nextSeq = () => ++seq;

    const buildSessionEvents = (game, durationMs, fingerprint, launchSignature, heartbeatSession) => {
        const sessionId = uuid();
        const now = Date.now();
        const start = Math.max(0, now - durationMs);
        const winExe = game.win_exe || `${game.name.toLowerCase().replace(/[^a-z0-9]+/g, "")}.exe`;
        const jitter = Math.floor(Math.random() * 450) + 120;
        return [
            {
                type: "running_game_heartbeat",
                properties: {
                    client_track_timestamp: start,
                    client_heartbeat_session_id: heartbeatSession,
                    event_sequence_number: nextSeq(),
                    game_id: game.id, game_name: game.name, game_metadata: null,
                    game_executable: winExe, game_detection_enabled: true,
                    initial_heartbeat: true, final_heartbeat: false,
                    game_session_id: sessionId, duration_tracked_ms: 0,
                    rtc_connection_id: null, media_session_id: null,
                    launch_signature: launchSignature, client_app_state: "focused",
                    client_send_timestamp: start
                }
            },
            {
                type: "launch_game",
                properties: {
                    client_track_timestamp: start + jitter,
                    client_heartbeat_session_id: heartbeatSession,
                    event_sequence_number: nextSeq(),
                    game: game.name, game_id: game.id, verified: true, elevated: false,
                    is_launcher: false, game_platform: "desktop",
                    detection_method: "verified_game", is_overlay_enabled: false,
                    is_overlay_game_enabled: true, is_overlay_game_source: "OOP_DEFAULT_DATABASE",
                    fullscreen_type: "UNKNOWN", hardware_display_count: 1,
                    overlay_method: "Disabled", activity_status_enabled: true,
                    activity_status_shared_guilds: [], current_user_status: "online",
                    game_detection_enabled: true, executable_path: winExe,
                    voice_channel_id: null, voice_channel_type: null,
                    voice_channel_bitrate: null, voice_channel_guild_id: null,
                    hidden_by_distributor: false, game_metadata: null,
                    executable_fingerprint: fingerprint,
                    client_performance_cpu: null, client_performance_memory: null,
                    cpu_core_count: null, accessibility_features: 0,
                    rendered_locale: "en-US", launch_signature: launchSignature,
                    client_rtc_state: null, client_app_state: "focused",
                    client_send_timestamp: start + jitter
                }
            },
            {
                type: "running_game_heartbeat",
                properties: {
                    client_track_timestamp: now,
                    client_heartbeat_session_id: heartbeatSession,
                    event_sequence_number: nextSeq(),
                    game_id: game.id, game_name: game.name, game_metadata: null,
                    game_executable: winExe, game_detection_enabled: true,
                    initial_heartbeat: false, final_heartbeat: true,
                    game_session_id: sessionId, duration_tracked_ms: durationMs,
                    rtc_connection_id: null, media_session_id: null,
                    launch_signature: launchSignature, client_app_state: "focused",
                    client_send_timestamp: now
                }
            }
        ];
    };

    try {
        const req = getWebpackRequire();
        if (!req?.c) throw new Error("Webpack not found.");
        const exports = collectExports(req);
        const runStore = findStore(exports, "RunningGameStore");
        const dispatcher = findDispatcher(exports);
        if (!runStore || !dispatcher) throw new Error("RunningGameStore/Dispatcher not found.");
        const detectableStore = findStore(exports, "DetectableGameStore");
        const authStore = findStore(exports, "AuthenticationStore");
        const userStore = findStore(exports, "UserStore");

        const GAMES = await loadGames(detectableStore);
        const meta = readClientMeta(exports);
        const launchSignature = uuid();
        const heartbeatSession = uuid();
        const clientLaunchId = uuid();
        const superProps = buildSuperProps(meta, launchSignature, heartbeatSession, clientLaunchId);

        const token = getToken(authStore, exports);
        if (!token) throw new Error("Token not found.");
        const userId = getUserId(token, authStore, userStore);
        if (!userId) throw new Error("User ID not found.");
        const analyticsToken = await getAnalyticsToken(token, superProps);
        if (!analyticsToken) throw new Error("analytics_token not found.");
        const fingerprint = await generateFingerprint(userId);
        const currentAuth = { token, userId, analyticsToken, fingerprint, superProps };

        const durationMs = AUTO_CLAIM_HOURS * 3600 * 1000;
        let claimed = 0;
        const total = GAMES.length;

        console.log(`[MGP] Claiming ${total} games in batches of ${BATCH_SIZE}...`);

        for (let i = 0; i < total; i += BATCH_SIZE) {
            const chunk = GAMES.slice(i, i + BATCH_SIZE);
            const events = chunk.flatMap(game =>
                buildSessionEvents(game, durationMs, fingerprint, launchSignature, heartbeatSession)
            );
            let ok = false;
            try { ok = await postScienceEvents(events, currentAuth); } catch (err) {
                console.warn(`[MGP] Batch ${i}–${i + chunk.length} error: ${err.message}`);
            }
            if (ok) {
                claimed += chunk.length;
                console.log(`[MGP] Progress: ${claimed}/${total} ✓`);
            } else {
                console.warn(`[MGP] Batch ${i}–${i + chunk.length} failed.`);
            }
            if (BATCH_DELAY_MS > 0 && i + BATCH_SIZE < total) await sleep(BATCH_DELAY_MS);
        }

        console.log(`[MGP] ✓ Done! ${claimed}/${total} games claimed.`);
        delete window[LOCK];
    } catch (err) {
        delete window[LOCK];
        console.error("[MGP]", err);
    }
})();