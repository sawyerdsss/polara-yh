import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import compression from "compression";
import { bootstrap } from "@mercuryworkshop/proxy-bootstrap";
import { chatRouter } from "./chat.js";
import { musicRouter } from "./music.js";
import { presenceRouter } from "./presence.js";
import { AD_HOSTS } from "./adhosts.js";
import { rateLimit, securityHeaders, configureWisp, guardUpgrades } from "./security.js";
import * as usage from "./usage.js";

// A public site must not go down because one odd connection hit a bug: log it and keep serving.
process.on("uncaughtException", (err) => console.error("Unexpected error (still running):", err));
process.on("unhandledRejection", (err) => console.error("Unexpected rejection (still running):", err));

// Scramjet bootstrap: serves /sw.js, /bootstrap-init.js, /controller/*, /scram/*,
// /clients/* and the /wisp/ websocket that the proxy tunnels traffic through.
configureWisp();
const { routeRequest, routeUpgrade } = await bootstrap();

const app = express();
const PORT = process.env.PORT || 3030;
app.disable("x-powered-by");

// Hosts put a reverse proxy in front of the app, so every visitor would look like the same IP address (and share rate limits).
// By default the forwarded-address header is trusted when it comes from a local/private proxy (Caddy, Docker, most hosts).
// Behind Cloudflare or another public CDN, set TRUST_PROXY to the number of proxies in front of the app (usually 1 or 2).
const TRUST = process.env.TRUST_PROXY;
app.set("trust proxy", TRUST ? (/^\d+$/.test(TRUST) ? Number(TRUST) : TRUST) : "loopback, linklocal, uniquelocal");
const visitorIp = (req) => (TRUST ? String(req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress : req.socket.remoteAddress);

app.use(securityHeaders);

// ---- bandwidth: count every byte sent (see `npm run usage`), and stop single visitors from mirroring the games ----
app.use((req, res, next) => {
	const p = req.path;
	const cat = p.startsWith("/api/img") ? "img" : p.startsWith("/api/") ? "api" : p.startsWith("/games/") ? "games" : "static";
	if ((cat === "games" || cat === "static") && usage.staticBlocked(req.ip)) {
		return res.status(429).set("Retry-After", "3600").type("text/plain").send("Download limit reached for today. Try again tomorrow.");
	}
	const write = res.write.bind(res);
	const end = res.end.bind(res);
	const size = (c) => (c == null || typeof c === "function" ? 0 : Buffer.byteLength(c));
	res.write = (c, ...a) => {
		usage.add(cat, size(c), req.ip);
		return write(c, ...a);
	};
	res.end = (c, ...a) => {
		usage.add(cat, size(c), req.ip);
		return end(c, ...a);
	};
	next();
});

// gzip/deflate text, scripts, JSON and wasm (images, video and already-compressed files are skipped automatically)
app.use(
	compression({
		threshold: 1024,
		level: 5,
		filter: (req, res) => {
			if (req.headers.range) return false; // partial downloads must stay byte-exact
			if (req.path.startsWith("/api/chat/stream")) return false; // live chat stream
			return compression.filter(req, res);
		},
	}),
);

// the proxy's runtime files (scramjet, controller, transports) are the same for everyone: let browsers keep them
app.use((req, res, next) => {
	if (/^\/(scram|controller|clients)\//.test(req.path)) res.setHeader("Cache-Control", "public, max-age=21600");
	next();
});
app.use((req, res, next) => {
	if (routeRequest(req, res)) return;
	next();
});

// chat has no limits at all, so it is mounted before the shared rate limiter below
app.use("/api/chat", chatRouter());
app.use("/api", rateLimit({ windowMs: 60e3, max: 300 }));
app.use("/api/music", musicRouter());
app.use("/api/presence", presenceRouter());
app.get("/healthz", (req, res) => res.type("text/plain").send("ok"));

// Google Fonts catalog for the font picker (via fontsource's public metadata), cached for a day
let fonts = null;
let fontsAt = 0;
app.get("/api/fonts", async (req, res) => {
	try {
		if (!fonts || Date.now() - fontsAt > 864e5) {
			const r = await fetch("https://api.fontsource.org/v1/fonts?type=google", { signal: AbortSignal.timeout(12000) });
			if (!r.ok) throw new Error(`fontsource ${r.status}`);
			const list = await r.json();
			fonts = list.map((f) => [f.family, f.category, f.weights]);
			fontsAt = Date.now();
		}
		res.set("Cache-Control", "public, max-age=3600").json(fonts);
	} catch {
		if (fonts) return res.json(fonts);
		res.status(502).json({ error: "Font catalog unavailable" });
	}
});

// ---- image proxy: lets the WebGL rain effect read remote background images (browsers block that without CORS) ----
function privateAddress(ip) {
	if (net.isIPv6(ip)) {
		const l = ip.toLowerCase();
		if (l === "::" || l === "::1" || l.startsWith("fc") || l.startsWith("fd") || /^fe[89ab]/.test(l)) return true;
		const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
		return m ? privateAddress(m[1]) : false;
	}
	const [a, b] = ip.split(".").map(Number);
	return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}
// checked at connection time, so a hostname can't switch to an internal address between the check and the request
function guardedLookup(hostname, options, cb) {
	dns.lookup(hostname, { all: true }).then(
		(addrs) => {
			if (!addrs.length || addrs.some((a) => privateAddress(a.address))) return cb(new Error("blocked address"));
			if (options && options.all) cb(null, addrs);
			else cb(null, addrs[0].address, addrs[0].family);
		},
		(err) => cb(err),
	);
}
const IMG_TYPE = /^image\/(png|jpe?g|webp|gif|avif)(;|$)/i;
// recently fetched images are kept in memory so the same background isn't downloaded from its host again for every visitor
const imgCache = new Map();
let imgCacheBytes = 0;
const IMG_CACHE_MAX = 120e6;
function cacheImage(key, value) {
	imgCache.set(key, { ...value, at: Date.now() });
	imgCacheBytes += value.buf.length;
	for (const [k, v] of imgCache) {
		if (imgCacheBytes <= IMG_CACHE_MAX) break;
		imgCache.delete(k);
		imgCacheBytes -= v.buf.length;
	}
}
function fetchImage(url, hops = 0) {
	return new Promise((resolve, reject) => {
		if (hops > 3 || !/^https?:$/.test(url.protocol)) return reject(new Error("bad url"));
		if (net.isIP(url.hostname) && privateAddress(url.hostname)) return reject(new Error("blocked address"));
		const lib = url.protocol === "https:" ? https : http;
		const req = lib.get(url, { lookup: guardedLookup, timeout: 15000, headers: { "User-Agent": "Mozilla/5.0 (Polaris image proxy)", Accept: "image/*" } }, (res) => {
			if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
				res.resume();
				try {
					return resolve(fetchImage(new URL(res.headers.location, url), hops + 1));
				} catch (e) {
					return reject(e);
				}
			}
			const type = res.headers["content-type"] || "";
			if (res.statusCode !== 200 || !IMG_TYPE.test(type)) {
				res.resume();
				return reject(new Error("not an image"));
			}
			const chunks = [];
			let size = 0;
			res.on("data", (c) => {
				size += c.length;
				if (size > 12e6) return req.destroy(new Error("too large"));
				chunks.push(c);
			});
			res.on("end", () => resolve({ type: type.split(";")[0], buf: Buffer.concat(chunks) }));
			res.on("error", reject);
		});
		req.on("timeout", () => req.destroy(new Error("timeout")));
		req.on("error", reject);
	});
}
app.get("/api/img", rateLimit({ windowMs: 60e3, max: 40 }), async (req, res) => {
	try {
		const url = new URL(String(req.query.u || ""));
		let hit = imgCache.get(url.href);
		if (hit && Date.now() - hit.at > 864e5) hit = null;
		if (!hit) {
			hit = await fetchImage(url);
			cacheImage(url.href, hit);
		}
		const { type, buf } = hit;
		res.set({
			"Content-Type": type,
			"Cache-Control": "public, max-age=604800",
			"X-Content-Type-Options": "nosniff",
			"Content-Security-Policy": "default-src 'none'; sandbox",
		}).send(buf);
	} catch {
		res.status(502).end();
	}
});

// ---- static files: only the site itself is public (never server code, data, dotfiles or package files) ----
const PUBLIC = /^\/(?:$|index\.html$|games\.js$|robots\.txt$|games\/|vendor\/)/;
// a few emulator games (Pokemon, Zelda, Metroid, ...) load the shared EmulatorJS files from /emulatorjs/ instead of next to themselves
app.use((req, res, next) => {
	if (req.url.startsWith("/emulatorjs/")) req.url = "/games/selenite" + req.url;
	next();
});
app.use((req, res, next) => (PUBLIC.test(req.path) ? next() : res.status(404).end()));

// Game pages get vendor/guard.js inlined at the top. Plenty of them pull in ad and tracking code (Google ads, cdn.r9x.in, ...),
// which would otherwise run on Polaris' own origin next to the chat session; the guard stops those hosts from loading.
const GUARD = "<script>" + fs.readFileSync(path.join(import.meta.dirname, "vendor", "guard.js"), "latin1").replace("[/*HOSTS*/]", JSON.stringify(AD_HOSTS)) + "</script>";
const AD_HOST = new RegExp("(^|\\.)(" + AD_HOSTS.map((h) => h.replace(/\./g, "\\.")).join("|") + ")$", "i");
// scripts written straight into the page are loaded before the guard can see them, so those tags are taken out here
const AD_SCRIPT = /<script\b[^>]*\bsrc\s*=\s*["']?(?:https?:)?\/\/([^\/"'\s>]+)[^>]*>\s*<\/script>/gi;
const GAMES_DIR = path.join(import.meta.dirname, "games");
app.use("/games", async (req, res, next) => {
	if (req.method !== "GET" && req.method !== "HEAD") return next();
	let rel;
	try {
		rel = decodeURIComponent(req.path);
	} catch {
		return next();
	}
	if (rel.endsWith("/")) rel += "index.html";
	if (!/\.html?$/i.test(rel)) return next();
	const file = path.join(GAMES_DIR, rel);
	if (!file.startsWith(GAMES_DIR + path.sep)) return next();
	let page;
	try {
		page = (await fs.promises.readFile(file)).toString("latin1"); // latin1 keeps every byte exactly as it was
	} catch {
		return next();
	}
	page = page.replace(AD_SCRIPT, (tag, host) => (AD_HOST.test(host) ? "" : tag));
	// insert after <head> (or <html>/doctype) so the page keeps its rendering mode
	const at = /<head[^>]*>/i.exec(page) || /<html[^>]*>/i.exec(page) || /^\s*<!doctype[^>]*>/i.exec(page);
	const i = at ? at.index + at[0].length : 0;
	res.set({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=604800" });
	res.send(Buffer.from(page.slice(0, i) + GUARD + page.slice(i), "latin1"));
});
app.use(
	express.static(import.meta.dirname, {
		dotfiles: "deny",
		// the page itself is re-checked on every visit (cheap 304 if unchanged); heavy files are kept by the browser
		setHeaders(res, file) {
			const rel = path.relative(import.meta.dirname, file).replace(/\\/g, "/");
			if (rel === "index.html" || rel === "games.js") res.setHeader("Cache-Control", "no-cache");
			else if (rel.startsWith("vendor/")) res.setHeader("Cache-Control", "public, max-age=2592000");
			else if (rel.startsWith("games/")) res.setHeader("Cache-Control", "public, max-age=604800");
		},
	}),
);

// never leak stack traces
app.use((err, req, res, next) => {
	if (res.headersSent) return next(err);
	res.status(err.status >= 400 && err.status < 500 ? err.status : 500).json({ error: "That request couldn't be processed." });
});

const server = http.createServer(app);
server.requestTimeout = 60e3;
server.headersTimeout = 20e3;
server.maxHeadersCount = 100;
guardUpgrades(server, routeUpgrade, visitorIp);

server.on("error", (err) => {
	if (err.code === "EADDRINUSE") {
		console.error(`\nPolaris can't start: port ${PORT} is already in use.\nAnother copy is probably still running. Close its window (or end node.exe in Task Manager) and run start.bat again.\n`);
	} else {
		console.error(err);
	}
	process.exit(1);
});

server.listen(PORT, () => {
	console.log(`Polaris is running on http://localhost:${PORT}`);
	console.log(usage.summary());
});
