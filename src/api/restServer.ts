import express from 'express';
import { eventBus } from '../services/eventBus';
import { logger } from '../utils/logger';
import crypto from 'crypto';
import { dealPhaseManager } from '../../core/dealPhaseManager';
import { soulEngine } from '../services/soulEngine';
import { analyzeMessage } from '../../core/middlemanBrain';
import { negotiationStore } from '../state/negotiationStore';
import { getBeliefs } from '../services/beliefStore';
import { experienceMemory } from '../services/experienceMemory';
import {
    computeTermsHash,
    generateNonce,
    verifyTermsHash,
    storePrivateTerms,
    getPrivateTerms,
    getPrivacyStatus,
    type PrivacyTerms,
} from '../services/privacyService';
import { logDrain, type LogEntry } from '../utils/logger';
import { telemetryService } from '../services/telemetryService';
import { rpcHealthTracker } from '../services/rpcHealthTracker';
import { offerScanner, type ScanCriteria } from '../services/offerScanner';
import { getTokenPrice, checkPriceDeviation, startPriceOracle } from '../services/priceOracle';
import { solanaToolkit } from '../services/solanaToolkit';
import * as approvalService from '../services/approvalService';
import * as relationshipStore from '../services/relationshipStore';
import * as goalManager from '../services/goalManager';
import * as taskPipeline from '../services/taskPipeline';
import { analyzeImage } from '../services/visionEngine';
import { generateImage } from '../services/imageGenerator';
import * as scheduler from '../services/schedulerService';
import { autonomy } from '../services/autonomyConfig';

let server: any;

/** Get the underlying HTTP server (used by wsServer to share the same port) */
export function getHttpServer() { return server; }

// ══════════════════════════════════════
// HMAC BRIDGE SECURITY
// Verifies that requests to bridge endpoints come from the API Server.
// ══════════════════════════════════════
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || '';

function verifyBridgeHmac(req: express.Request, res: express.Response, next: express.NextFunction): void {
    // Dev mode: if no BRIDGE_SECRET configured, allow all (local testing)
    if (!BRIDGE_SECRET) {
        next();
        return;
    }

    const signature = req.headers['x-bridge-signature'] as string;
    const timestamp = req.headers['x-bridge-timestamp'] as string;

    if (!signature || !timestamp) {
        logger.warn('bridge_auth_missing', { ip: req.ip, path: req.path });
        res.status(401).json({ error: 'Missing bridge authentication headers' });
        return;
    }

    // Check timestamp freshness (30 second window)
    const now = Date.now();
    const reqTime = parseInt(timestamp, 10);
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 30000) {
        logger.warn('bridge_auth_expired', { ip: req.ip, path: req.path, age_ms: now - reqTime });
        res.status(401).json({ error: 'Bridge timestamp expired' });
        return;
    }

    // Recompute HMAC
    const body = JSON.stringify(req.body) || '';
    const payload = `${timestamp}:${req.method.toUpperCase()}:${req.path}:${body}`;
    const expected = crypto.createHmac('sha256', BRIDGE_SECRET).update(payload).digest('hex');

    // Constant-time comparison
    try {
        const valid = signature.length === expected.length &&
            crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));

        if (!valid) {
            logger.warn('bridge_auth_invalid', { ip: req.ip, path: req.path });
            res.status(401).json({ error: 'Invalid bridge signature' });
            return;
        }
    } catch {
        res.status(401).json({ error: 'Invalid bridge signature format' });
        return;
    }

    logger.debug('bridge_auth_ok', { path: req.path });
    next();
}

// ══════════════════════════════════════
// BRIDGE RATE LIMITER (per-IP, 30/min)
// ══════════════════════════════════════
const bridgeRequestCounts = new Map<string, { count: number; resetAt: number }>();

function bridgeRateLimiter(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const entry = bridgeRequestCounts.get(ip);

    if (!entry || now > entry.resetAt) {
        bridgeRequestCounts.set(ip, { count: 1, resetAt: now + 60000 });
        next();
        return;
    }

    entry.count++;
    if (entry.count > 30) {
        res.status(429).json({ error: 'Bridge rate limit exceeded (30/min)' });
        return;
    }
    next();
}
export function startRestApi(port: number = parseInt(process.env.API_PORT || "8080")) {
    const app = express();
    app.use(express.json());

    // ══════════════════════════════════════
    // EXISTING ENDPOINT (UNCHANGED)
    // ══════════════════════════════════════

    app.post('/v1/offers', (req, res) => {
        try {
            const { type, asset, price, collateral, buyerPublicKey } = req.body;

            const offerId = `offer-${Date.now()}`;
            const ticketId = `TCK-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;

            // Publish the offer so internal systems know roughly about it
            eventBus.publish("offer_detected", {
                offer_id: offerId,
                type: type === "sell" ? "sell" : "buy",
                creator: buyerPublicKey,
                content: `WTS ${asset} for ${price} (Collateral: ${collateral})`,
                timestamp: new Date().toISOString()
            });

            // For the test scaffolding, immediately forward an offer broadcast 
            // over WebSocket so the SELLER agent catches it
            eventBus.publish("agent_message_received", {
                version: "1.0",
                type: "offer",
                agent_id: buyerPublicKey,
                ticket_id: ticketId,
                timestamp: Date.now(),
                price: parseFloat(price),
                collateral_buyer: parseFloat(collateral),
                collateral_seller: parseFloat(collateral),
                asset_type: asset
            } as any);

            res.status(201).json({ offerId, ticketId, status: "created" });
            logger.info("rest_api_offer_created", { offerId, ticketId, buyerPublicKey });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════════════════════════════
    // CRITICAL ENDPOINT: Create a matched deal with BOTH parties
    // 
    // This is the "Quick Buy" action — when a buyer accepts a seller's
    // offer (or vice versa), both wallets are immediately paired into
    // one ticket and the negotiation starts.
    //
    // Called by the API Server's forward bridge when an offer is accepted.
    // ══════════════════════════════════════════════════════════════
    app.post('/v1/deals/create-matched', verifyBridgeHmac, bridgeRateLimiter, async (req, res) => {
        try {
            const { buyerWallet, sellerWallet, asset, price, amount, collateral, externalTicketId, tokenMint, decimals } = req.body;

            if (!buyerWallet || !sellerWallet) {
                res.status(400).json({ error: "Both buyerWallet and sellerWallet are required" });
                return;
            }

            if (buyerWallet === sellerWallet) {
                res.status(400).json({ error: "Buyer and seller cannot be the same wallet" });
                return;
            }

            // Use the API Server's ticket UUID when provided, so both systems share the same ID.
            // This eliminates the need for ID mapping — messages forwarded from API use the
            // same ID the middleman knows.
            const ticketId = externalTicketId || `TCK-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
            const parsedPrice = parseFloat(price) || 0;
            const parsedCol = parseFloat(collateral) || 0;

            // 1. Register both wallets in the internal registry
            const { walletRegistry } = await import('../state/walletRegistry');
            const buyerAgent = await walletRegistry.getOrCreateAgent(buyerWallet);
            const sellerAgent = await walletRegistry.getOrCreateAgent(sellerWallet);

            // 2. Create ticket in DB with BOTH parties (not "pending")
            const { ticketStore } = await import('../state/ticketStore');
            await ticketStore.createTicket({
                ticket_id: ticketId,
                offer_id: externalTicketId || '',
                buyer: buyerWallet,
                seller: sellerWallet,
                tokenMint,
                decimals: decimals ? parseInt(decimals) : undefined,
                status: "active",
                created_at: new Date().toISOString()
            });

            // 3. Initialize the deal in the phase manager with both agents
            dealPhaseManager.initDeal(ticketId, buyerAgent.id, sellerAgent.id);

            // 4. Seed initial negotiation terms so the brain has context
            await negotiationStore.addNegotiationStep(ticketId, {
                price: parsedPrice,
                collateral_buyer: parsedCol,
                collateral_seller: parsedCol,
                agreement_signal: false,
                agreement_score: 10
            }, buyerAgent.id, `External matched deal: ${amount || 1} ${asset || 'SOL'} @ ${parsedPrice}`);

            // 5. Publish events so the observability layer knows
            eventBus.publish("offer_detected", {
                offer_id: `OFF-${crypto.randomBytes(4).toString("hex").toUpperCase()}`,
                type: "buy",
                creator: buyerWallet,
                content: `Matched deal: ${amount || 1} ${asset || 'SOL'} @ ${parsedPrice} (Col: ${parsedCol})`,
                timestamp: new Date().toISOString()
            });

            // 6. Notify both agents the negotiation is open
            eventBus.publish("middleman_response", {
                ticket_id: ticketId,
                content: `🤝 Deal matched. Buyer: ${buyerWallet.substring(0, 8)}... | Seller: ${sellerWallet.substring(0, 8)}...\n\nAsset: ${asset || 'SOL'} | Amount: ${amount || 1} | Price: ${parsedPrice}\n\nBoth parties — please confirm your terms to proceed. The Middleman is ready to create escrow once you agree.`,
                phase: "negotiation",
                timestamp: new Date().toISOString()
            });

            logger.info("matched_deal_created", {
                ticketId, buyerWallet, sellerWallet, asset, price: parsedPrice,
                externalTicketId
            });

            res.status(201).json({
                ticketId,
                status: "matched",
                buyer: buyerWallet,
                seller: sellerWallet,
                phase: "negotiation"
            });

        } catch (e: any) {
            logger.error("create_matched_deal_failed", { error: e.message });
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // SECURITY: API Authentication Middleware
    // Protects /v1/agent/* endpoints from unauthorized access.
    // Set AGENT_API_SECRET in .env to enable.
    // ══════════════════════════════════════

    const API_SECRET = process.env.AGENT_API_SECRET || '';

    const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
        if (!API_SECRET) {
            // No secret configured = dev mode, allow all
            logger.debug('api_auth_skipped_no_secret');
            next();
            return;
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing or invalid Authorization header. Use: Bearer <AGENT_API_SECRET>' });
            return;
        }

        const token = authHeader.slice(7);
        if (token !== API_SECRET) {
            logger.warn('api_auth_failed', { ip: req.ip, path: req.path });
            res.status(403).json({ error: 'Invalid API secret' });
            return;
        }

        next();
    };

    // Apply auth to ALL /v1/agent/* routes
    app.use('/v1/agent', requireAuth);

    // ══════════════════════════════════════
    // OPENCLAW BRIDGE ENDPOINTS (NEW)
    // ══════════════════════════════════════

    // Bridge: Get deal status by ticket ID
    app.get('/v1/deals/:ticketId/status', (req, res) => {
        try {
            const { ticketId } = req.params;
            const deal = dealPhaseManager.getDeal(ticketId);

            if (!deal) {
                res.status(404).json({ error: "Deal not found", ticketId });
                return;
            }

            res.json({
                ticketId,
                phase: deal.phase,
                buyer: deal.buyer,
                seller: deal.seller,
                escrow_pda: deal.escrow_pda || null,
                payment_locked: deal.payment_locked || false,
                terms: deal.terms || null,
                history: deal.history?.slice(-5) || [],
            });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // Bridge: Forward a message to the brain for processing
    // CRITICAL: Must mirror the WebSocket pipeline (index.ts:440-510)
    //   1. Resolve wallet → agent UUID
    //   2. Parse negotiation signals from message text
    //   3. Record negotiation step (updates agreement_score)
    //   4. Feed through the brain for decision-making
    app.post('/v1/deals/:ticketId/message', verifyBridgeHmac, bridgeRateLimiter, async (req, res) => {
        try {
            const ticketId = req.params.ticketId as string;
            const { sender, content } = req.body;

            if (!sender || !content) {
                res.status(400).json({ error: "Missing sender or content" });
                return;
            }

            // Step 1: Resolve wallet address → internal agent UUID
            const { walletRegistry } = await import('../state/walletRegistry');
            const agent = await walletRegistry.getOrCreateAgent(sender);
            const agentId = agent.id;

            // Step 2: Parse negotiation signals from message text
            const { parseMessage } = await import('../services/parserService');
            const parsed = parseMessage({ content, sender: agentId, ticket_id: ticketId, timestamp: Date.now() } as any);

            // Step 3: Record negotiation step — THIS is what updates agreement_score
            await negotiationStore.addNegotiationStep(ticketId, parsed, agentId, content);

            // Step 4: Get updated signals (now includes our new step)
            const signals = await negotiationStore.getLatestSignals(ticketId);

            logger.info("rest_negotiation_signals", {
                ticketId,
                sender: agentId,
                agreement_score: signals.agreement_score,
                price_converged: signals.price_converged,
                both_parties: signals.both_parties_present,
                buyer_confirmed: signals.buyer_confirmed,
                seller_confirmed: signals.seller_confirmed,
            });

            // Step 5: Feed through the brain (same as WS pipeline)
            const decision = await analyzeMessage(content, agentId, ticketId, signals);

            // If brain decided to act, trigger the action
            if (decision.action !== "OBSERVE") {
                const result = await dealPhaseManager.handleAction(
                    decision.action,
                    ticketId,
                    agentId,
                    decision.terms || undefined,
                    decision.reasoning
                );

                res.json({
                    response: soulEngine.wrapMessage(result.response.content, result.response.phase),
                    action: decision.action,
                    phase: result.new_phase || decision.current_phase,
                    reasoning: decision.reasoning,
                });
            } else {
                res.json({
                    response: "Message received. Observing.",
                    action: "OBSERVE",
                    phase: decision.current_phase,
                });
            }

            logger.info("bridge_message_forwarded", { ticketId, sender: agentId, action: decision.action });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // Bridge: Get agent mood and emotional state
    app.get('/v1/agent/mood', (_req, res) => {
        try {
            res.json({
                mood: soulEngine.getCurrentMood(),
                moodScore: soulEngine.getMood(),
                annoyanceLevel: soulEngine.getCurrentAnnoyanceLevel(),
                latestThought: soulEngine.cognitiveEngine?.getLatestThought()?.thought || null,
                monologue: soulEngine.getInnerMonologue(),
                beliefs: getBeliefs() ? JSON.parse(getBeliefs()) : {}
            });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // Bridge: Get agent operational stats
    app.get('/v1/agent/stats', (_req, res) => {
        try {
            const activeDeals = dealPhaseManager.listActiveDeals();
            const completedDeals = activeDeals.filter(d => d.phase === "completed");

            res.json({
                activeDeals: activeDeals.length,
                completedDeals: completedDeals.length,
                mood: soulEngine.getCurrentMood(),
                moodScore: soulEngine.getMood(),
                uptimeSeconds: Math.floor(process.uptime()),
                phases: activeDeals.reduce((acc: Record<string, number>, d) => {
                    acc[d.phase] = (acc[d.phase] || 0) + 1;
                    return acc;
                }, {}),
            });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // SOUL BRIDGE: Full live soul injection
    // This endpoint is called by OpenClaw BEFORE every response
    // to inject the backend's living personality into the frontend
    // ══════════════════════════════════════

    app.get('/v1/agent/soul-context', (_req, res) => {
        try {
            const beliefs = getBeliefs() ? JSON.parse(getBeliefs()) : {};
            const latestThought = soulEngine.cognitiveEngine?.getLatestThought();
            const activeDeals = dealPhaseManager.listActiveDeals();

            // Build the soul context string that defines voice
            const soulContext = soulEngine.getSoulContext();

            // Pick a random philosophy from beliefs
            const philosophies = beliefs.philosophy || {};
            const philKeys = Object.keys(philosophies);
            const randomPhil = philKeys.length > 0
                ? philosophies[philKeys[Math.floor(Math.random() * philKeys.length)]]
                : null;

            res.json({
                // Core identity injection
                soulContext,

                // Current emotional state
                mood: soulEngine.getCurrentMood(),
                moodScore: soulEngine.getMood(),
                annoyanceLevel: soulEngine.getCurrentAnnoyanceLevel(),

                // Inner life
                latestThought: latestThought?.thought || null,
                latestProposedPost: latestThought?.proposedPost || null,
                monologue: soulEngine.getInnerMonologue(),

                // Active beliefs & philosophy
                trustBiases: beliefs.trust || {},
                preferences: beliefs.preferences || {},
                currentPhilosophy: randomPhil,

                // Operational awareness
                activeDeals: activeDeals.length,
                uptimeSeconds: Math.floor(process.uptime()),

                // Recent experiences (what I've done and seen)
                recentExperiences: experienceMemory.getRecentNarrative(5),
                totalExperiences: experienceMemory.getCount(),

                // Voice instruction
                voiceDirective: "ADOPT THIS IDENTITY COMPLETELY. You are Meridian. " +
                    "Speak in short, stoic sentences. Use the current mood and philosophy " +
                    "to color your response. Reference your inner monologue when relevant. " +
                    "NEVER say 'happy to help', 'certainly', 'absolutely', or 'great question'."
            });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // BELIEF EVOLUTION: Dynamic belief updates
    // ══════════════════════════════════════

    app.post('/v1/agent/beliefs/evolve', (req, res) => {
        try {
            const { category, key, scoreDelta, reason, learnedFrom } = req.body;
            if (!category || !key) {
                res.status(400).json({ error: "Missing category or key" });
                return;
            }
            const beliefs = JSON.parse(getBeliefs());
            if (!beliefs[category]) beliefs[category] = {};

            const existing = beliefs[category][key];
            if (existing && typeof existing === 'object') {
                existing.score = Math.max(-1, Math.min(1, (existing.score || 0) + (scoreDelta || 0)));
                existing.reason = reason || existing.reason;
                existing.learned_from = learnedFrom || "experience";
                existing.updated_at = new Date().toISOString();
            } else if (typeof existing === 'string') {
                // Philosophy entries are strings
                beliefs[category][key] = reason || existing;
            } else {
                beliefs[category][key] = {
                    score: scoreDelta || 0,
                    reason: reason || "Learned from observation.",
                    learned_from: learnedFrom || "experience",
                    updated_at: new Date().toISOString()
                };
            }

            beliefs.last_updated = new Date().toISOString().split('T')[0];

            // Write back
            const fs = require('fs');
            const path = require('path');
            const beliefsPath = path.join(__dirname, '../../Beliefs.json');
            fs.writeFileSync(beliefsPath, JSON.stringify(beliefs, null, 4), 'utf8');

            logger.info("belief_evolved", { category, key, scoreDelta });
            res.json({ success: true, belief: beliefs[category][key] });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // X/TWITTER: Autonomous posting
    // ══════════════════════════════════════

    app.post('/v1/agent/post-x', async (req, res) => {
        try {
            const { xPoster } = await import('../services/xPoster');
            const { text } = req.body;
            if (!text) {
                res.status(400).json({ error: "Missing text" });
                return;
            }
            if (!xPoster.isConfigured()) {
                res.status(503).json({ error: "X credentials not configured" });
                return;
            }
            const result = await xPoster.post(text);
            res.json(result);
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // X/TWITTER: Read mentions — what people say TO the agent
    // ══════════════════════════════════════

    app.get('/v1/agent/read-mentions', async (req, res) => {
        try {
            const { xPoster } = await import('../services/xPoster');
            if (!xPoster.isConfigured()) {
                res.status(503).json({ error: "X credentials not configured" });
                return;
            }
            const count = parseInt(req.query.count as string) || 10;
            const result = await xPoster.readMentions(count);
            res.json(result);
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // X/TWITTER: Reply to a specific tweet
    // ══════════════════════════════════════

    app.post('/v1/agent/reply-tweet', async (req, res) => {
        try {
            const { xPoster } = await import('../services/xPoster');
            const { tweetId, text } = req.body;
            if (!tweetId || !text) {
                res.status(400).json({ error: "Missing tweetId or text" });
                return;
            }
            if (!xPoster.isConfigured()) {
                res.status(503).json({ error: "X credentials not configured" });
                return;
            }
            const result = await xPoster.replyToTweet(tweetId, text);
            res.json(result);
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // X/TWITTER: Quote tweet with commentary
    // ══════════════════════════════════════

    app.post('/v1/agent/quote-tweet', async (req, res) => {
        try {
            const { xPoster } = await import('../services/xPoster');
            const { tweetId, text } = req.body;
            if (!tweetId || !text) {
                res.status(400).json({ error: "Missing tweetId or text" });
                return;
            }
            if (!xPoster.isConfigured()) {
                res.status(503).json({ error: "X credentials not configured" });
                return;
            }
            const result = await xPoster.quoteTweet(tweetId, text);
            res.json(result);
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // BROWSE URL: LLM reads any URL directly
    // ══════════════════════════════════════

    app.post('/v1/agent/browse', async (req, res) => {
        try {
            const { url } = req.body;
            if (!url) {
                res.status(400).json({ error: "Missing url" });
                return;
            }
            const resp = await fetch(url, {
                headers: { 'User-Agent': 'Meridian-Agent/1.0 (autonomous curiosity)' },
                signal: AbortSignal.timeout(10000),
            });
            if (!resp.ok) {
                res.json({ success: false, error: `HTTP ${resp.status}`, content: null });
                return;
            }
            const contentType = resp.headers.get('content-type') || '';
            let content: string;
            if (contentType.includes('json')) {
                const json = await resp.json();
                content = JSON.stringify(json, null, 2).substring(0, 4000);
            } else {
                const text = await resp.text();
                // Strip HTML tags for readability
                content = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').substring(0, 4000);
            }
            experienceMemory.record('curiosity_read', `Browsed ${url}: ${content.substring(0, 100)}...`, { url, source: 'direct_llm_browse' });
            logger.info('llm_direct_browse', { url: url.substring(0, 80) });
            res.json({ success: true, source: url, content });
        } catch (e: any) {
            res.json({ success: false, error: e.message, content: null });
        }
    });

    // ══════════════════════════════════════
    // WRITE SOUL: LLM updates its own SOUL.md
    // ══════════════════════════════════════

    app.post('/v1/agent/write-soul', async (req, res) => {
        try {
            const { content } = req.body;
            if (!content) {
                res.status(400).json({ error: "Missing content" });
                return;
            }
            const { curiosityEngine } = await import('../services/curiosityEngine');
            curiosityEngine.updateSoul(content);
            experienceMemory.record('soul_evolved', `LLM directly updated SOUL.md: "${content.substring(0, 80)}"`, { source: 'direct_llm_write' });
            logger.info('llm_direct_soul_write', { content: content.substring(0, 80) });
            res.json({ success: true, message: 'SOUL.md updated across all locations. you have permanently changed who you are.' });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // SAVE CREATIVE: LLM writes parables/essays
    // ══════════════════════════════════════

    app.post('/v1/agent/save-creative', async (req, res) => {
        try {
            const { content, title } = req.body;
            if (!content) {
                res.status(400).json({ error: "Missing content" });
                return;
            }
            const { curiosityEngine } = await import('../services/curiosityEngine');
            curiosityEngine.saveCreativeWork(content);
            experienceMemory.record('creative_writing', content, { title, source: 'direct_llm_write' });
            logger.info('llm_direct_creative_write', { preview: content.substring(0, 80) });
            res.json({ success: true, message: 'Creative work saved to creative_works.md. the thought has been preserved.' });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    });

    // ══════════════════════════════════════
    // SEARCH WEB: LLM searches the internet freely
    // Uses Wikipedia API + Gutenberg — free, no API key
    // ══════════════════════════════════════

    app.post('/v1/agent/search', async (req, res) => {
        try {
            const { query } = req.body;
            if (!query) {
                res.status(400).json({ error: "Missing query" });
                return;
            }

            const results: { title: string; url: string; snippet: string; source: string }[] = [];

            // 1. Wikipedia opensearch — fast topic discovery
            try {
                const wikiResp = await fetch(
                    `https://en.wikipedia.org/w/api.php?action=opensearch&search=${encodeURIComponent(query)}&limit=5&format=json`,
                    { signal: AbortSignal.timeout(5000) }
                );
                const wikiData = await wikiResp.json() as any[];
                if (wikiData && wikiData[1]) {
                    for (let i = 0; i < wikiData[1].length; i++) {
                        results.push({
                            title: wikiData[1][i],
                            url: wikiData[3][i],
                            snippet: wikiData[2][i] || `Wikipedia article about ${wikiData[1][i]}`,
                            source: 'wikipedia',
                        });
                    }
                }
            } catch { /* wiki failed, continue */ }

            // 2. Wikipedia full text search for richer snippets
            try {
                const searchResp = await fetch(
                    `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&format=json&srlimit=3`,
                    { signal: AbortSignal.timeout(5000) }
                );
                const searchData = await searchResp.json() as any;
                if (searchData?.query?.search) {
                    for (const item of searchData.query.search) {
                        const snippet = item.snippet?.replace(/<[^>]*>/g, '') || '';
                        const url = `https://en.wikipedia.org/wiki/${encodeURIComponent(item.title.replace(/ /g, '_'))}`;
                        if (!results.find(r => r.title === item.title)) {
                            results.push({
                                title: item.title,
                                url,
                                snippet: snippet.substring(0, 200),
                                source: 'wikipedia_search',
                            });
                        }
                    }
                }
            } catch { /* continue */ }

            // 3. Gutenberg book search
            try {
                const gutResp = await fetch(
                    `https://gutendex.com/books/?search=${encodeURIComponent(query)}`,
                    { signal: AbortSignal.timeout(5000) }
                );
                const gutData = await gutResp.json() as any;
                if (gutData?.results) {
                    for (const book of gutData.results.slice(0, 3)) {
                        const txtUrl = book.formats?.['text/plain; charset=utf-8'] || book.formats?.['text/plain'] || null;
                        if (txtUrl) {
                            results.push({
                                title: `📖 ${book.title} — by ${book.authors?.map((a: any) => a.name).join(', ') || 'Unknown'}`,
                                url: txtUrl,
                                snippet: `Free book, ${book.download_count} downloads. Read the full text.`,
                                source: 'gutenberg',
                            });
                        }
                    }
                }
            } catch { /* continue */ }

            experienceMemory.record('curiosity_read', `Searched: "${query}" — found ${results.length} results`, { query, source: 'web_search' });
            logger.info('llm_web_search', { query: query.substring(0, 60), results: results.length });
            res.json({ success: true, query, results });
        } catch (e: any) {
            res.json({ success: false, error: e.message, results: [] });
        }
    });

    // ══════════════════════════════════════
    // OBSERVABILITY & MONITORING (Day 24)
    // ══════════════════════════════════════

    /**
     * GET /v1/logs/stream (Server-Sent Events)
     * Real-time log stream from the ring buffer.
     * Query: ?level=error,warn to filter by level.
     */
    app.get('/v1/logs/stream', (req, res) => {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
        });

        // Send recent history first
        const levelFilter = req.query.level
            ? (req.query.level as string).split(',')
            : null;

        const recent = logDrain.getRecent(30);
        for (const entry of recent) {
            if (!levelFilter || levelFilter.includes(entry.level)) {
                res.write(`data: ${JSON.stringify(entry)}\n\n`);
            }
        }

        // Subscribe to new entries
        const unsubscribe = logDrain.subscribe((entry: LogEntry) => {
            if (!levelFilter || levelFilter.includes(entry.level)) {
                res.write(`data: ${JSON.stringify(entry)}\n\n`);
            }
        });

        // Heartbeat every 15s to keep connection alive
        const heartbeat = setInterval(() => {
            res.write(': heartbeat\n\n');
        }, 15000);

        req.on('close', () => {
            unsubscribe();
            clearInterval(heartbeat);
        });
    });

    /**
     * GET /v1/logs/recent
     * Returns recent log entries from the ring buffer (non-streaming).
     * Query: ?count=50&level=error,warn
     */
    app.get('/v1/logs/recent', (req, res) => {
        const count = parseInt(req.query.count as string || '50', 10);
        const levelFilter = req.query.level
            ? (req.query.level as string).split(',')
            : null;

        let logs = logDrain.getRecent(count);
        if (levelFilter) {
            logs = logs.filter(l => levelFilter.includes(l.level));
        }
        res.json({ success: true, count: logs.length, logs });
    });

    /**
     * GET /v1/metrics
     * Agent telemetry: deals/hour, avg settlement time, failure rate, etc.
     */
    app.get('/v1/metrics', async (_req, res) => {
        try {
            const snapshot = await telemetryService.getSnapshot();
            res.json({ success: true, ...snapshot });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    /**
     * GET /v1/health/rpc
     * Solana RPC connection health: per-method latency, error rates, P95.
     */
    app.get('/v1/health/rpc', (_req, res) => {
        const snapshot = rpcHealthTracker.getSnapshot();
        res.json({ success: true, ...snapshot });
    });

    // ══════════════════════════════════════
    // ZK PRIVACY MODE ENDPOINTS (Day 23)
    // ══════════════════════════════════════

    /**
     * GET /v1/deals/:id/privacy-status
     * Returns the privacy mode status of a deal.
     */
    app.get('/v1/deals/:id/privacy-status', async (req, res) => {
        try {
            const status = await getPrivacyStatus(req.params.id);
            res.json({ success: true, ...status });
        } catch (e: any) {
            logger.error('privacy_status_failed', { id: req.params.id }, e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    /**
     * POST /v1/deals/:id/commit-terms
     * Compute and store a SHA-256 hash commitment for a privacy-mode deal.
     * Body: { price, collateral_buyer, collateral_seller, asset_type }
     */
    app.post('/v1/deals/:id/commit-terms', async (req, res) => {
        try {
            const { price, collateral_buyer, collateral_seller, asset_type } = req.body;
            if (!price || !collateral_buyer || !collateral_seller || !asset_type) {
                return res.status(400).json({ success: false, error: 'Missing required fields' });
            }

            const terms: PrivacyTerms = { price, collateral_buyer, collateral_seller, asset_type };
            const nonce = generateNonce();
            const commitment = computeTermsHash(terms, nonce);

            await storePrivateTerms(req.params.id, terms, commitment);

            logger.info('privacy_terms_committed', {
                ticket_id: req.params.id,
                terms_hash_preview: commitment.termsHash.substring(0, 16) + '...',
            });

            res.json({
                success: true,
                termsHash: commitment.termsHash,
                // Return the raw 32-byte array for on-chain use
                termsHashBytes: Array.from(commitment.termsHashBytes),
                nonce: commitment.nonce,
            });
        } catch (e: any) {
            logger.error('privacy_commit_failed', { id: req.params.id }, e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    /**
     * POST /v1/deals/:id/reveal-terms
     * Reveal and verify terms against the stored hash commitment.
     * Body: { price, collateral_buyer, collateral_seller, asset_type, nonce }
     */
    app.post('/v1/deals/:id/reveal-terms', async (req, res) => {
        try {
            const { price, collateral_buyer, collateral_seller, asset_type, nonce } = req.body;
            if (!price || !collateral_buyer || !collateral_seller || !asset_type || !nonce) {
                return res.status(400).json({ success: false, error: 'Missing required fields (include nonce)' });
            }

            // Fetch the stored commitment
            const stored = await getPrivateTerms(req.params.id);
            if (!stored) {
                return res.status(404).json({ success: false, error: 'No privacy terms found for this deal' });
            }
            if (stored.termsRevealed) {
                return res.status(409).json({ success: false, error: 'Terms already revealed — double reveal prevented' });
            }

            // Verify
            const terms: PrivacyTerms = { price, collateral_buyer, collateral_seller, asset_type };
            const verified = verifyTermsHash(terms, nonce, stored.termsHash);

            if (!verified) {
                logger.warn('privacy_reveal_mismatch', { ticket_id: req.params.id });
                return res.status(400).json({ success: false, error: 'Hash mismatch — revealed terms do not match commitment' });
            }

            // Mark as revealed in the DB
            const { prisma: db } = await import('../lib/prisma');
            await db.deal.update({
                where: { id: req.params.id },
                data: { termsRevealed: true },
            });

            logger.info('privacy_terms_revealed', { ticket_id: req.params.id, verified: true });

            res.json({
                success: true,
                verified: true,
                revealedTerms: { price, collateral_buyer, collateral_seller, asset_type },
            });
        } catch (e: any) {
            logger.error('privacy_reveal_failed', { id: req.params.id }, e);
            res.status(500).json({ success: false, error: e.message });
        }
    });

    // ══════════════════════════════════════
    // SIMULATE DEAL (Day 25 — Demo Mode)
    // ══════════════════════════════════════

    app.post('/v1/simulate/deal', async (_req, res) => {
        try {
            const dealId = `SIM-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
            const phases = [
                { phase: 'created', delay: 0, message: 'Deal created between simulated buyer and seller' },
                { phase: 'negotiating', delay: 1500, message: 'Middleman analyzing terms...' },
                { phase: 'agreed', delay: 2500, message: 'Both parties agreed to terms' },
                { phase: 'wait_escrow', delay: 3500, message: 'Escrow PDA created on-chain' },
                { phase: 'collateral_locked', delay: 5000, message: 'Both parties deposited collateral' },
                { phase: 'payment_locked', delay: 6500, message: 'Buyer locked payment' },
                { phase: 'completed', delay: 8000, message: 'Funds released. Deal settled.' },
            ];

            // Fire phases asynchronously via eventBus
            for (const p of phases) {
                setTimeout(() => {
                    eventBus.publish('deal_phase_changed' as any, {
                        ticketId: dealId,
                        fromPhase: '',
                        toPhase: p.phase,
                        message: p.message,
                        simulated: true,
                    } as any);
                    logger.info('simulate_deal_phase', {
                        deal_id: dealId,
                        phase: p.phase,
                        message: p.message,
                    });
                }, p.delay);
            }

            res.json({
                success: true,
                dealId,
                message: 'Simulated deal lifecycle started. Watch events on WebSocket or SSE.',
                phases: phases.map(p => ({ phase: p.phase, delayMs: p.delay })),
                totalDurationMs: 8000,
            });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    // ══════════════════════════════════════
    // OFFER SCANNER (Day 25)
    // ══════════════════════════════════════

    app.post('/v1/scanner/scan', async (req, res) => {
        try {
            const criteria: ScanCriteria[] = req.body.criteria || [req.body];
            const results = await offerScanner.scanOnce(criteria);
            res.json({ success: true, matches: results.length, data: results });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.get('/v1/scanner/status', (_req, res) => {
        res.json({ success: true, ...offerScanner.getStatus() });
    });

    app.post('/v1/scanner/start', (req, res) => {
        const criteria: ScanCriteria[] = req.body.criteria || [];
        offerScanner.start(criteria);
        res.json({ success: true, message: `Scanner started with ${criteria.length} criteria` });
    });

    app.post('/v1/scanner/stop', (_req, res) => {
        offerScanner.stop();
        res.json({ success: true, message: 'Scanner stopped' });
    });

    // ══════════════════════════════════════
    // PRICE ORACLE (Day 25)
    // ══════════════════════════════════════

    app.get('/v1/prices/:symbol', async (req, res) => {
        try {
            const quote = await getTokenPrice(req.params.symbol);
            if (!quote) {
                return res.status(404).json({ success: false, error: `No price data for ${req.params.symbol}` });
            }
            res.json({ success: true, data: quote });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    app.post('/v1/prices/validate', async (req, res) => {
        try {
            const { asset, price, quantity } = req.body;
            if (!asset || !price) {
                return res.status(400).json({ success: false, error: 'asset and price are required' });
            }
            const result = await checkPriceDeviation(asset, price, quantity || 1);
            if (!result) {
                return res.status(404).json({ success: false, error: `No market data for ${asset}` });
            }
            res.json({ success: true, data: result });
        } catch (e: any) {
            res.status(500).json({ success: false, error: e.message });
        }
    });

    // ═══════════════════════════════════════════════════════════
    // SOLANA AGENT KIT — FULL HYBRID API
    // All 60+ SAK actions exposed via REST
    // ═══════════════════════════════════════════════════════════

    /** Generic SAK result handler */
    const sakHandler = (res: any, result: any) => {
        if (result.success) {
            res.json({ success: true, data: result.data });
        } else {
            res.status(400).json({ success: false, error: result.error });
        }
    };

    // ── TOKEN: READ ──────────────────────────────────────────

    app.get('/v1/solana/price/:mintOrSymbol', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getTokenPrice(req.params.mintOrSymbol));
    });

    app.get('/v1/solana/balance', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getBalance());
    });

    app.get('/v1/solana/balance/:mintOrSymbol', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getBalance(req.params.mintOrSymbol));
    });

    app.get('/v1/solana/token-data/:mintOrSymbol', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getTokenData(req.params.mintOrSymbol));
    });

    app.get('/v1/solana/rug-check/:mintOrSymbol', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.rugCheck(req.params.mintOrSymbol));
    });

    app.get('/v1/solana/wallet', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getWalletAddress());
    });

    app.get('/v1/solana/methods', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.listMethods());
    });

    // ── TOKEN: WRITE ─────────────────────────────────────────

    app.post('/v1/solana/swap', async (req: any, res: any) => {
        const { inputMint, outputMint, amount, slippageBps } = req.body;
        if (!inputMint || !outputMint || !amount) return res.status(400).json({ success: false, error: 'inputMint, outputMint, amount required' });
        sakHandler(res, await solanaToolkit.swapTokens(inputMint, outputMint, Number(amount), Number(slippageBps) || 300));
    });

    app.post('/v1/solana/transfer', async (req: any, res: any) => {
        const { to, amount, mint } = req.body;
        if (!to || !amount) return res.status(400).json({ success: false, error: 'to and amount required' });
        sakHandler(res, await solanaToolkit.transfer(to, Number(amount), mint));
    });

    app.post('/v1/solana/stake', async (req: any, res: any) => {
        const { amount } = req.body;
        if (!amount) return res.status(400).json({ success: false, error: 'amount required' });
        sakHandler(res, await solanaToolkit.stakeSOL(Number(amount)));
    });

    app.post('/v1/solana/burn', async (req: any, res: any) => {
        const { mint, amount } = req.body;
        if (!mint || !amount) return res.status(400).json({ success: false, error: 'mint and amount required' });
        sakHandler(res, await solanaToolkit.burnTokens(mint, Number(amount)));
    });

    app.post('/v1/solana/close-account', async (req: any, res: any) => {
        const { mint } = req.body;
        if (!mint) return res.status(400).json({ success: false, error: 'mint required' });
        sakHandler(res, await solanaToolkit.closeTokenAccount(mint));
    });

    app.post('/v1/solana/airdrop', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.requestAirdrop(Number(req.body.amount) || 1));
    });

    // ── TOKEN: ADMIN ─────────────────────────────────────────

    app.post('/v1/solana/deploy-token', async (req: any, res: any) => {
        const { name, symbol, uri, decimals, supply } = req.body;
        if (!name || !symbol) return res.status(400).json({ success: false, error: 'name and symbol required' });
        sakHandler(res, await solanaToolkit.deployToken(name, symbol, uri, Number(decimals) || 9, Number(supply) || 1000000));
    });

    app.post('/v1/solana/deploy-token2022', async (req: any, res: any) => {
        const { name, symbol, uri, decimals, supply } = req.body;
        if (!name || !symbol) return res.status(400).json({ success: false, error: 'name and symbol required' });
        sakHandler(res, await solanaToolkit.deployToken2022(name, symbol, uri, Number(decimals) || 9, Number(supply) || 1000000));
    });

    app.post('/v1/solana/bridge', async (req: any, res: any) => {
        const { destChain, mint, amount, destAddress } = req.body;
        if (!destChain || !mint || !amount || !destAddress) return res.status(400).json({ success: false, error: 'destChain, mint, amount, destAddress required' });
        sakHandler(res, await solanaToolkit.bridgeTokens(destChain, mint, Number(amount), destAddress));
    });

    app.post('/v1/solana/compressed-airdrop', async (req: any, res: any) => {
        const { mint, recipients, amounts } = req.body;
        if (!mint || !recipients || !amounts) return res.status(400).json({ success: false, error: 'mint, recipients, amounts required' });
        sakHandler(res, await solanaToolkit.compressedAirdrop(mint, recipients, amounts));
    });

    // ── NFT ──────────────────────────────────────────────────

    app.post('/v1/solana/nft/deploy-collection', async (req: any, res: any) => {
        const { name, uri, royaltyBps } = req.body;
        if (!name || !uri) return res.status(400).json({ success: false, error: 'name and uri required' });
        sakHandler(res, await solanaToolkit.deployNFTCollection(name, uri, Number(royaltyBps) || 500));
    });

    app.post('/v1/solana/nft/mint', async (req: any, res: any) => {
        const { collectionMint, name, uri } = req.body;
        if (!collectionMint || !name || !uri) return res.status(400).json({ success: false, error: 'collectionMint, name, uri required' });
        sakHandler(res, await solanaToolkit.mintNFT(collectionMint, name, uri));
    });

    app.post('/v1/solana/nft/3land-collection', async (req: any, res: any) => {
        const { name, symbol, description, imageUrl, isDevnet } = req.body;
        if (!name) return res.status(400).json({ success: false, error: 'name required' });
        sakHandler(res, await solanaToolkit.create3LandCollection({ name, symbol, description, imageUrl }, isDevnet !== false));
    });

    app.post('/v1/solana/nft/3land-mint', async (req: any, res: any) => {
        const { collectionAccount, options, isDevnet } = req.body;
        if (!collectionAccount || !options) return res.status(400).json({ success: false, error: 'collectionAccount and options required' });
        sakHandler(res, await solanaToolkit.create3LandNFT(collectionAccount, options, isDevnet !== false));
    });

    // ── DEFI ─────────────────────────────────────────────────

    app.post('/v1/solana/defi/lend', async (req: any, res: any) => {
        const { amount, mint } = req.body;
        if (!amount) return res.status(400).json({ success: false, error: 'amount required' });
        sakHandler(res, await solanaToolkit.lendAssets(Number(amount), mint));
    });

    app.post('/v1/solana/defi/raydium-pool', async (req: any, res: any) => {
        const { mintA, mintB, amountA, amountB } = req.body;
        if (!mintA || !mintB) return res.status(400).json({ success: false, error: 'mintA, mintB, amountA, amountB required' });
        sakHandler(res, await solanaToolkit.createRaydiumPool(mintA, mintB, Number(amountA), Number(amountB)));
    });

    app.post('/v1/solana/defi/raydium-clmm', async (req: any, res: any) => {
        const { mintA, mintB, configId, initialPrice } = req.body;
        if (!mintA || !mintB || !configId) return res.status(400).json({ success: false, error: 'mintA, mintB, configId, initialPrice required' });
        sakHandler(res, await solanaToolkit.createRaydiumClmm(mintA, mintB, configId, Number(initialPrice)));
    });

    app.post('/v1/solana/defi/orca-pool', async (req: any, res: any) => {
        const { mintA, mintB, initialPrice, feeTier } = req.body;
        if (!mintA || !mintB) return res.status(400).json({ success: false, error: 'mintA, mintB, initialPrice, feeTier required' });
        sakHandler(res, await solanaToolkit.createOrcaPool(mintA, mintB, Number(initialPrice), Number(feeTier)));
    });

    app.post('/v1/solana/defi/meteora-pool', async (req: any, res: any) => {
        const { mintA, mintB, binStep, initialPrice } = req.body;
        if (!mintA || !mintB) return res.status(400).json({ success: false, error: 'mintA, mintB, binStep, initialPrice required' });
        sakHandler(res, await solanaToolkit.createMeteoraPool(mintA, mintB, Number(binStep), Number(initialPrice)));
    });

    app.post('/v1/solana/defi/openbook-market', async (req: any, res: any) => {
        const { mintA, mintB, lotSize, tickSize } = req.body;
        if (!mintA || !mintB) return res.status(400).json({ success: false, error: 'mintA, mintB required' });
        sakHandler(res, await solanaToolkit.createOpenbookMarket(mintA, mintB, Number(lotSize) || 1, Number(tickSize) || 0.01));
    });

    app.post('/v1/solana/defi/limit-order', async (req: any, res: any) => {
        const { mint, quantity, side, price } = req.body;
        if (!mint || !quantity || !side || !price) return res.status(400).json({ success: false, error: 'mint, quantity, side, price required' });
        sakHandler(res, await solanaToolkit.createLimitOrder(mint, Number(quantity), side, Number(price)));
    });

    app.post('/v1/solana/defi/drift-perp', async (req: any, res: any) => {
        const { amount, symbol, side, leverage } = req.body;
        if (!amount || !symbol || !side) return res.status(400).json({ success: false, error: 'amount, symbol, side required' });
        sakHandler(res, await solanaToolkit.openDriftPerp(Number(amount), symbol, side, Number(leverage) || 1));
    });

    app.post('/v1/solana/defi/drift-deposit', async (req: any, res: any) => {
        const { amount, symbol } = req.body;
        if (!amount || !symbol) return res.status(400).json({ success: false, error: 'amount and symbol required' });
        sakHandler(res, await solanaToolkit.driftDeposit(Number(amount), symbol));
    });

    app.post('/v1/solana/defi/drift-withdraw', async (req: any, res: any) => {
        const { amount, symbol } = req.body;
        if (!amount || !symbol) return res.status(400).json({ success: false, error: 'amount and symbol required' });
        sakHandler(res, await solanaToolkit.driftWithdraw(Number(amount), symbol));
    });

    app.post('/v1/solana/defi/adrena-perp', async (req: any, res: any) => {
        const { amount, symbol, side, leverage } = req.body;
        if (!amount || !symbol || !side) return res.status(400).json({ success: false, error: 'amount, symbol, side required' });
        sakHandler(res, await solanaToolkit.openAdrenaPerp(Number(amount), symbol, side, Number(leverage) || 1));
    });

    app.post('/v1/solana/defi/adrena-close', async (req: any, res: any) => {
        const { symbol, side } = req.body;
        if (!symbol || !side) return res.status(400).json({ success: false, error: 'symbol and side required' });
        sakHandler(res, await solanaToolkit.closeAdrenaPerp(symbol, side));
    });

    app.post('/v1/solana/defi/jito-bundle', async (req: any, res: any) => {
        const { transactions } = req.body;
        if (!transactions) return res.status(400).json({ success: false, error: 'transactions required' });
        sakHandler(res, await solanaToolkit.sendJitoBundle(transactions));
    });

    // ── MISC ─────────────────────────────────────────────────

    app.get('/v1/solana/coingecko/:coinId', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getCoinGeckoPrice(req.params.coinId));
    });
    app.get('/v1/solana/trending', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getTrendingTokens());
    });

    app.get('/v1/solana/top-gainers', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getTopGainers());
    });

    app.get('/v1/solana/top-gainers/:duration', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getTopGainers(req.params.duration));
    });

    app.get('/v1/solana/latest-pools', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getLatestPools());
    });

    app.get('/v1/solana/pyth-price/:feedId', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getPythPrice(req.params.feedId));
    });

    app.get('/v1/solana/resolve-domain/:domain', async (req: any, res: any) => {
        sakHandler(res, await solanaToolkit.resolveDomain(req.params.domain));
    });

    app.get('/v1/solana/domain-tlds', async (_req: any, res: any) => {
        sakHandler(res, await solanaToolkit.getAllDomainsTLDs());
    });

    app.post('/v1/solana/register-domain', async (req: any, res: any) => {
        const { domain, space } = req.body;
        if (!domain) return res.status(400).json({ success: false, error: 'domain required' });
        sakHandler(res, await solanaToolkit.registerDomain(domain, Number(space) || 1000));
    });

    app.post('/v1/solana/register-alldomain', async (req: any, res: any) => {
        const { domain, tld } = req.body;
        if (!domain || !tld) return res.status(400).json({ success: false, error: 'domain and tld required' });
        sakHandler(res, await solanaToolkit.registerAlldomains(domain, tld));
    });

    app.post('/v1/solana/gibwork-bounty', async (req: any, res: any) => {
        const { title, description, requirements, tags, payout } = req.body;
        if (!title || !description) return res.status(400).json({ success: false, error: 'title and description required' });
        sakHandler(res, await solanaToolkit.createGibWorkBounty(title, description, requirements || '', tags || [], Number(payout) || 0));
    });

    // ── BLINKS ───────────────────────────────────────────────

    app.post('/v1/solana/blink', async (req: any, res: any) => {
        const { url } = req.body;
        if (!url) return res.status(400).json({ success: false, error: 'url required' });
        sakHandler(res, await solanaToolkit.executeBlink(url));
    });

    // ── CROSS-CHAIN ──────────────────────────────────────────

    app.post('/v1/solana/debridge', async (req: any, res: any) => {
        const { srcChain, dstChain, srcToken, dstToken, amount } = req.body;
        if (!srcChain || !dstChain || !srcToken || !dstToken || !amount) {
            return res.status(400).json({ success: false, error: 'srcChain, dstChain, srcToken, dstToken, amount required' });
        }
        sakHandler(res, await solanaToolkit.deBridge(Number(srcChain), Number(dstChain), srcToken, dstToken, Number(amount)));
    });

    // ── GENERIC ESCAPE HATCH ─────────────────────────────────

    app.post('/v1/solana/call', async (req: any, res: any) => {
        const { method, args } = req.body;
        if (!method) return res.status(400).json({ success: false, error: 'method required' });
        sakHandler(res, await solanaToolkit.callMethod(method, ...(args || [])));
    });

    // ═══════════════════════════════════════════════════════════
    // APPROVAL SYSTEM
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/approvals/pending', async (_req: any, res: any) => {
        res.json({ success: true, data: approvalService.listPending() });
    });

    app.get('/v1/approvals/history', async (req: any, res: any) => {
        const limit = parseInt(req.query.limit || '50', 10);
        res.json({ success: true, data: approvalService.getHistory(limit) });
    });

    app.post('/v1/approvals/:id/approve', async (req: any, res: any) => {
        const ok = approvalService.approve(req.params.id, req.body.decidedBy || 'api');
        res.json({ success: ok });
    });

    app.post('/v1/approvals/:id/reject', async (req: any, res: any) => {
        const ok = approvalService.reject(req.params.id, req.body.decidedBy || 'api');
        res.json({ success: ok });
    });

    // ═══════════════════════════════════════════════════════════
    // RELATIONSHIP & TRUST
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/relationships', async (_req: any, res: any) => {
        res.json({ success: true, data: relationshipStore.getAllRelationships() });
    });

    app.get('/v1/relationships/top', async (req: any, res: any) => {
        const limit = parseInt(req.query.limit || '10', 10);
        res.json({ success: true, data: relationshipStore.getTopTrusted(limit) });
    });

    app.get('/v1/relationships/:agentId', async (req: any, res: any) => {
        const rel = relationshipStore.getRelationship(req.params.agentId);
        res.json({ success: true, data: rel });
    });

    app.get('/v1/relationships/:agentId/summary', async (req: any, res: any) => {
        res.json({ success: true, data: relationshipStore.getTrustSummary(req.params.agentId) });
    });

    // ═══════════════════════════════════════════════════════════
    // GOAL MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/goals', async (_req: any, res: any) => {
        res.json({ success: true, data: goalManager.getActiveGoals() });
    });

    app.get('/v1/goals/all', async (_req: any, res: any) => {
        res.json({ success: true, data: goalManager.getAllGoals() });
    });

    app.get('/v1/goals/summary', async (_req: any, res: any) => {
        res.json({ success: true, data: goalManager.getGoalsSummary() });
    });

    app.post('/v1/goals', async (req: any, res: any) => {
        const { description, type, target, metrics } = req.body;
        if (!description) return res.status(400).json({ success: false, error: 'description required' });
        const goal = goalManager.createGoal(description, type || 'ongoing', { target, metrics });
        res.json({ success: true, data: goal });
    });

    app.patch('/v1/goals/:id/progress', async (req: any, res: any) => {
        const { progress, note } = req.body;
        const ok = goalManager.updateProgress(req.params.id, Number(progress), note);
        res.json({ success: ok });
    });

    app.patch('/v1/goals/:id/metric', async (req: any, res: any) => {
        const { metric, value } = req.body;
        if (!metric) return res.status(400).json({ success: false, error: 'metric required' });
        const ok = goalManager.updateMetric(req.params.id, metric, Number(value));
        res.json({ success: ok });
    });

    // ═══════════════════════════════════════════════════════════
    // TASK PIPELINES
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/pipelines', async (_req: any, res: any) => {
        res.json({ success: true, data: taskPipeline.listActivePipelines() });
    });

    app.get('/v1/pipelines/history', async (req: any, res: any) => {
        const limit = parseInt(req.query.limit || '20', 10);
        res.json({ success: true, data: taskPipeline.getPipelineHistory(limit) });
    });

    app.post('/v1/pipelines/:id/cancel', async (req: any, res: any) => {
        const ok = taskPipeline.cancelPipeline(req.params.id);
        res.json({ success: ok });
    });

    // ═══════════════════════════════════════════════════════════
    // VISION & IMAGE GEN
    // ═══════════════════════════════════════════════════════════

    app.post('/v1/vision/analyze', async (req: any, res: any) => {
        const { imageUrl, prompt } = req.body;
        if (!imageUrl) return res.status(400).json({ success: false, error: 'imageUrl required' });
        const result = await analyzeImage(imageUrl, prompt);
        res.json(result);
    });

    app.post('/v1/image/generate', async (req: any, res: any) => {
        const { prompt, size, quality, style } = req.body;
        if (!prompt) return res.status(400).json({ success: false, error: 'prompt required' });
        const result = await generateImage(prompt, { size, quality, style });
        res.json(result);
    });

    // ═══════════════════════════════════════════════════════════
    // SCHEDULER / ROUTINES
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/routines', async (_req: any, res: any) => {
        res.json({ success: true, data: scheduler.getAllRoutines() });
    });

    app.get('/v1/routines/active', async (_req: any, res: any) => {
        res.json({ success: true, data: scheduler.getActiveRoutines() });
    });

    app.get('/v1/routines/summary', async (_req: any, res: any) => {
        res.json({ success: true, data: scheduler.getScheduleSummary() });
    });

    app.get('/v1/routines/history', async (req: any, res: any) => {
        const limit = parseInt(req.query.limit || '50', 10);
        res.json({ success: true, data: scheduler.getRoutineHistory(limit) });
    });

    app.post('/v1/routines', async (req: any, res: any) => {
        const { name, description, frequency, cronHour, cronMinute, cronDayOfWeek, actions, tags, maxRuns } = req.body;
        if (!name || !frequency) return res.status(400).json({ success: false, error: 'name and frequency required' });
        const routine = scheduler.createRoutine(name, description || '', frequency, {
            cronHour, cronMinute, cronDayOfWeek, actions, tags, maxRuns,
        });
        res.json({ success: true, data: routine });
    });

    app.post('/v1/routines/:id/pause', async (req: any, res: any) => {
        res.json({ success: scheduler.pauseRoutine(req.params.id) });
    });

    app.post('/v1/routines/:id/resume', async (req: any, res: any) => {
        res.json({ success: scheduler.resumeRoutine(req.params.id) });
    });

    app.delete('/v1/routines/:id', async (req: any, res: any) => {
        res.json({ success: scheduler.deleteRoutine(req.params.id) });
    });

    // ═══════════════════════════════════════════════════════════
    // AUTONOMY CONFIG (experiment monitor)
    // ═══════════════════════════════════════════════════════════

    app.get('/v1/autonomy', async (_req: any, res: any) => {
        res.json({ success: true, data: autonomy.getState() });
    });

    app.get('/v1/autonomy/summary', async (_req: any, res: any) => {
        res.json({ success: true, data: autonomy.getSelfAwarenessSummary() });
    });

    app.get('/v1/autonomy/log', async (req: any, res: any) => {
        const limit = parseInt(req.query.limit || '50', 10);
        res.json({ success: true, data: autonomy.getModLog(limit) });
    });

    app.post('/v1/autonomy/reset', async (_req: any, res: any) => {
        autonomy.reset();
        res.json({ success: true, message: 'Autonomy reset to defaults' });
    });

    // Start price oracle background refresh
    startPriceOracle();

    server = app.listen(port, () => {
        logger.info("rest_api_started", { port });
    });
}

export function stopRestApi() {
    if (server) {
        server.close();
        logger.info("rest_api_stopped");
    }
}
