import {
  HUD_SUMMARY_INSTRUCTIONS,
  keylessHudSummaryResponse,
} from '../../../src/hudSummaryResponse.js';
import { enforceRateLimit, openAiRateLimiter } from './rate-limit.js';
import { readRequestBody } from '../common/request.js';
import { OPENAI_HUD_SUMMARY_MODEL_DEFAULT } from './constants.js';

function extractOpenAiResponseText(data) {
  if (typeof data?.output_text === 'string' && data.output_text.trim()) {
    return data.output_text.trim();
  }
  if (!Array.isArray(data?.output)) return '';
  return data.output
    .flatMap((item) => (Array.isArray(item?.content) ? item.content : []))
    .map((part) => part?.text || part?.output_text || '')
    .join(' ')
    .trim();
}

function toFiveWordHudSummary(value) {
  return String(value || '')
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 5)
    .join(' ');
}

/**
 * Optional free / OpenAI-compatible backend for the HUD summary only
 * (see https://github.com/open-free-llm-api/awesome-freellm-apis).
 * Active when GEV_HUD_LLM_BASE_URL and GEV_HUD_LLM_API_KEY are both set;
 * otherwise the summary uses OpenAI exactly as before. Voice is unaffected.
 */
function freeHudLlmConfig() {
  const baseUrl = String(process.env.GEV_HUD_LLM_BASE_URL || '')
    .trim()
    .replace(/\/+$/, '');
  const apiKey = String(process.env.GEV_HUD_LLM_API_KEY || '').trim();
  const model = String(process.env.GEV_HUD_LLM_MODEL || '').trim();
  if (!baseUrl || !apiKey || !model) return null;
  return { baseUrl, apiKey, model };
}

function extractChatCompletionText(data) {
  const content = data?.choices?.[0]?.message?.content;
  return typeof content === 'string' ? content.trim() : '';
}

async function requestFreeHudSummary(config, context) {
  const response = await fetch(`${config.baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: config.model,
      messages: [
        { role: 'system', content: HUD_SUMMARY_INSTRUCTIONS },
        { role: 'user', content: JSON.stringify(context) },
      ],
      max_tokens: 100,
      temperature: 0.2,
    }),
  });
  const data = await response.json().catch(() => ({}));
  return { response, text: extractChatCompletionText(data) };
}

async function requestOpenAiHudSummary(apiKey, context) {
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model:
        process.env.OPENAI_HUD_SUMMARY_MODEL ||
        OPENAI_HUD_SUMMARY_MODEL_DEFAULT,
      instructions: HUD_SUMMARY_INSTRUCTIONS,
      input: JSON.stringify(context),
      reasoning: { effort: 'minimal' },
      max_output_tokens: 100,
    }),
  });
  const data = await response.json().catch(() => ({}));
  return { response, text: extractOpenAiResponseText(data) };
}

async function handleHudSummary(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const freeLlm = freeHudLlmConfig();
  const apiKey = process.env.OPENAI_API_KEY;
  const keyless = keylessHudSummaryResponse(freeLlm ? freeLlm.apiKey : apiKey);
  if (keyless) {
    res.statusCode = keyless.statusCode;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(keyless.payload));
    return;
  }

  // Per-IP throttle (GEV_RATELIMIT_OPENAI_PER_MIN). On by default; 0 disables.
  // Keyless HUD fallback has no provider cost and resolves above without
  // consuming a paid-endpoint quota slot.
  if (!enforceRateLimit(openAiRateLimiter(), req, res)) return;

  try {
    const body = await readRequestBody(req, 64 * 1024);
    const context = JSON.parse(body || '{}');
    const { response, text } = freeLlm
      ? await requestFreeHudSummary(freeLlm, context)
      : await requestOpenAiHudSummary(apiKey, context);
    const summary = toFiveWordHudSummary(text);
    res.statusCode = response.ok && summary ? 200 : response.status || 502;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    if (!response.ok)
      console.warn(`[hud-summary] upstream HTTP ${response.status}`);
    res.end(
      JSON.stringify({
        summary: summary || null,
        // Never relay `data.error.message`: provider wording carries request
        // ids, organization hints and quota phrasing.
        error: response.ok ? null : 'OpenAI HUD summary request failed',
      }),
    );
  } catch {
    console.warn('[hud-summary] request failed');
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: 'OpenAI HUD summary request failed',
      }),
    );
  }
}

export { handleHudSummary };
