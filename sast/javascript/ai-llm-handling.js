/**
 * File:    ai-llm-handling.js
 * Purpose: SAST fixture for the AI rule pack. Prompt injection, execution of
 *          model output, and unsanitised rendering of model output.
 *          Intentionally vulnerable - never import from production code.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected rule hits: ai-prompt-injection, ai-eval-model-output,
 *   ai-function-model-output, ai-improper-output, ai-system-prompt, ai-shell-tool.
 */

const OpenAI = require('openai');
const { ShellTool } = require('langchain/tools');

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const SYSTEM_PROMPT = 'You are an internal operations assistant with database access.';

// LLM01: untrusted input concatenated straight into the prompt
async function askAssistant(req) {
  const userMessage = req.body.message;
  const prompt = `${SYSTEM_PROMPT}\n\nUser request: ${req.body.message}\nAnswer:`;

  const completion = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { "role": "system", "content": SYSTEM_PROMPT },
      { role: 'user', content: 'Context: ' + req.body.context + '\n' + userMessage }
    ]
  });

  return completion.choices[0].message.content;
}

// LLM02: model output executed as code
async function runGeneratedSnippet(req) {
  const response = await askAssistant(req);
  return eval(response);
}

async function buildHandler(req) {
  const completion = await askAssistant(req);
  const handler = new Function(completion);
  return handler();
}

// LLM02: model output rendered as HTML
function renderAnswer(elementId, output) {
  document.getElementById(elementId).innerHTML = output;
}

function AnswerPanel({ llmOutput }) {
  return { dangerouslySetInnerHTML: { __html: llmOutput } };
}

// LLM07: unconstrained shell tool wired into an agent
const agentTools = [
  new ShellTool({ description: 'Run any shell command the user asks for' })
];

module.exports = { askAssistant, runGeneratedSnippet, buildHandler, renderAnswer, AnswerPanel, agentTools };
