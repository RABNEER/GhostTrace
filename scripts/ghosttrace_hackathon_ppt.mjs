#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

if (process.platform === "win32" && process.env.USERPROFILE) {
  process.env.HOME = process.env.USERPROFILE;
}

const DEFAULT_SKILL_DIR =
  "C:/Users/LOQ/.codex/plugins/cache/openai-primary-runtime/presentations/26.521.10419/skills/presentations";

const OUT = path.resolve(
  process.argv[2] || path.join(ROOT, "outputs", "ghosttrace_next_level_pitch.pptx"),
);

const SLIDE = { width: 1280, height: 720 };
const C = {
  ink: "#071018",
  ink2: "#0B1722",
  panel: "#101C28",
  panel2: "#142536",
  line: "#29445A",
  cyan: "#38D9FF",
  mint: "#5FF0A5",
  amber: "#FFD166",
  red: "#FF4D6D",
  violet: "#9B8CFF",
  text: "#F4F8FB",
  muted: "#90A4B8",
  dim: "#587085",
  white: "#FFFFFF",
};

const deck = [
  {
    kicker: "LIVE SECURITY",
    title: "GhostTrace exposes hidden process tampering before the host lies.",
    subtitle: "Kernel-level process integrity monitor for rootkits, injection, DKOM, and syscall-hook anomalies.",
    proof: "Hook telemetry + eBPF fallback + Go anomaly graph + AVX2 memory scanning.",
  },
  {
    kicker: "PROBLEM",
    title: "Modern malware does not need to be loud; it only needs to disappear.",
    bullets: [
      "Rootkits unlink tasks from normal process views.",
      "Injection hides payloads inside trusted processes.",
      "Syscall hooks bend telemetry before tools can read it.",
      "SOC teams see alerts late, without lineage or memory proof.",
    ],
  },
  {
    kicker: "THESIS",
    title: "Trust the cross-check, not one sensor.",
    subtitle: "GhostTrace compares kernel telemetry, /proc visibility, executable memory, and process lineage to catch contradictions.",
  },
  {
    kicker: "ARCHITECTURE",
    title: "The pipeline is built like a flight recorder for process behavior.",
    subtitle: "Small fixed frames flow through a lock-free ring buffer into a scoring graph and real-time operator UI.",
  },
  {
    kicker: "DETECTION ENGINE",
    title: "Five signals combine into one explainable risk score.",
    subtitle: "Every alert carries the PID, detail, score, and operator mitigation path.",
  },
  {
    kicker: "MEMORY SCAN",
    title: "Executable anonymous memory gets scanned where shellcode actually lives.",
    subtitle: "AVX2-assisted matching checks high-signal payload signatures without dragging the event pipeline.",
  },
  {
    kicker: "DEMO FLOW",
    title: "The hackathon demo is a clean 30-second story.",
    subtitle: "Start GhostTrace, launch benign executable-memory probe, watch alert stream, inspect lineage, export JSON.",
  },
  {
    kicker: "WHY IT WINS",
    title: "It feels like a real security product, not a toy detector.",
    bullets: [
      "Graceful shutdown restores native hooks.",
      "eBPF mode works as the safe production path.",
      "Webhook signatures make SIEM ingestion credible.",
      "TUI gives judges an instant visual payoff.",
    ],
  },
  {
    kicker: "ROADMAP",
    title: "From hackathon build to deployable host sensor.",
    subtitle: "The core is modular enough to grow into fleet policy, incident replay, and kernel-module research mode.",
  },
  {
    kicker: "CLOSE",
    title: "GhostTrace turns invisible process compromise into evidence you can act on.",
    subtitle: "Ask: approve a live demo slot, run it on a Linux VM, and judge it on detection speed plus explainability.",
  },
];

async function main() {
  const skillDir = process.env.PRESENTATIONS_SKILL_DIR || DEFAULT_SKILL_DIR;
  const utilsPath = path.join(skillDir, "scripts", "artifact_tool_utils.mjs");
  const utils = await import(pathToFileURL(utilsPath).href);

  await fs.mkdir(path.dirname(OUT), { recursive: true });
  await utils.ensureArtifactToolWorkspace(path.join(ROOT, "outputs", "presentation_workspace"));
  const artifact = await utils.importArtifactTool(path.join(ROOT, "outputs", "presentation_workspace"));
  const { Presentation, PresentationFile } = artifact;
  const presentation = Presentation.create({ slideSize: SLIDE });
  const ctx = utils.createSlideContext(artifact, {
    slideSize: SLIDE,
    workspaceDir: path.join(ROOT, "outputs", "presentation_workspace"),
    titleFont: "Aptos Display",
    bodyFont: "Aptos",
    monoFont: "Aptos Mono",
  });

  slideCover(presentation, ctx);
  slideProblem(presentation, ctx);
  slideCrossCheck(presentation, ctx);
  slideArchitecture(presentation, ctx);
  slideSignals(presentation, ctx);
  slideMemoryScan(presentation, ctx);
  slideDemo(presentation, ctx);
  slideWhyWins(presentation, ctx);
  slideRoadmap(presentation, ctx);
  slideClose(presentation, ctx);

  const pptx = await PresentationFile.exportPptx(presentation);
  await pptx.save(OUT);
  console.log(`Wrote ${OUT}`);
}

function addBg(ctx, slide, slideNo) {
  ctx.addShape(slide, { x: 0, y: 0, w: 1280, h: 720, fill: C.ink, line: ctx.line(C.ink, 0) });
  ctx.addShape(slide, { x: 0, y: 0, w: 1280, h: 720, fill: "#00000000", line: ctx.line(C.ink, 0) });
  for (let i = 0; i < 15; i++) {
    const x = 60 + i * 82;
    ctx.addShape(slide, { x, y: 676, w: 1, h: 10, fill: C.line, line: ctx.line(C.line, 0) });
  }
  ctx.addText(slide, {
    x: 1040,
    y: 664,
    w: 150,
    h: 18,
    text: `GHOSTTRACE / ${String(slideNo).padStart(2, "0")}`,
    fontSize: 9,
    color: C.dim,
    typeface: ctx.fonts.mono,
    align: "right",
  });
}

function kicker(ctx, slide, text, x = 72, y = 54) {
  ctx.addShape(slide, { x, y: y + 8, w: 30, h: 2, fill: C.cyan, line: ctx.line(C.cyan, 0) });
  ctx.addText(slide, {
    x: x + 42,
    y,
    w: 220,
    h: 20,
    text,
    fontSize: 11,
    bold: true,
    color: C.cyan,
    typeface: ctx.fonts.mono,
  });
}

function title(ctx, slide, text, y = 92, w = 960) {
  ctx.addText(slide, {
    x: 72,
    y,
    w,
    h: 118,
    text,
    fontSize: 42,
    bold: true,
    color: C.text,
    typeface: ctx.fonts.title,
    insets: { left: 0, right: 0, top: 0, bottom: 0 },
  });
}

function subtitle(ctx, slide, text, x = 72, y = 228, w = 680) {
  ctx.addText(slide, {
    x,
    y,
    w,
    h: 70,
    text,
    fontSize: 21,
    color: C.muted,
    typeface: ctx.fonts.body,
  });
}

function pill(ctx, slide, x, y, w, text, color) {
  ctx.addShape(slide, { x, y, w, h: 34, fill: C.panel, line: ctx.line(color, 1.2) });
  ctx.addText(slide, {
    x: x + 14,
    y: y + 8,
    w: w - 28,
    h: 18,
    text,
    fontSize: 11,
    bold: true,
    color,
    typeface: ctx.fonts.mono,
    align: "center",
  });
}

function metric(ctx, slide, x, y, value, label, color = C.cyan) {
  ctx.addText(slide, { x, y, w: 180, h: 52, text: value, fontSize: 38, bold: true, color, typeface: ctx.fonts.title });
  ctx.addText(slide, { x, y: y + 50, w: 190, h: 42, text: label, fontSize: 13, color: C.muted, typeface: ctx.fonts.body });
}

function box(ctx, slide, x, y, w, h, label, body, color = C.cyan) {
  ctx.addShape(slide, { x, y, w, h, fill: C.panel, line: ctx.line(C.line, 1) });
  ctx.addShape(slide, { x, y, w: 4, h, fill: color, line: ctx.line(color, 0) });
  ctx.addText(slide, { x: x + 18, y: y + 16, w: w - 34, h: 22, text: label, fontSize: 12, bold: true, color, typeface: ctx.fonts.mono });
  ctx.addText(slide, { x: x + 18, y: y + 46, w: w - 34, h: h - 58, text: body, fontSize: 17, color: C.text, typeface: ctx.fonts.body });
}

function slideCover(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 1);
  kicker(ctx, s, deck[0].kicker);
  ctx.addText(s, { x: 72, y: 112, w: 460, h: 62, text: "GhostTrace", fontSize: 58, bold: true, color: C.white, typeface: ctx.fonts.title });
  title(ctx, s, deck[0].title, 190, 760);
  subtitle(ctx, s, deck[0].subtitle, 72, 334, 650);
  pill(ctx, s, 72, 438, 150, "ASM HOOKS", C.cyan);
  pill(ctx, s, 240, 438, 150, "eBPF SAFE MODE", C.mint);
  pill(ctx, s, 408, 438, 170, "AVX2 SCANNER", C.amber);
  pill(ctx, s, 596, 438, 150, "GO ENGINE", C.violet);
  ctx.addShape(s, { x: 850, y: 124, w: 270, h: 270, geometry: "ellipse", fill: C.panel2, line: ctx.line(C.cyan, 1.5) });
  ctx.addShape(s, { x: 902, y: 176, w: 166, h: 166, geometry: "ellipse", fill: C.ink, line: ctx.line(C.red, 2) });
  ctx.addShape(s, { x: 970, y: 144, w: 28, h: 230, fill: C.cyan, line: ctx.line(C.cyan, 0) });
  ctx.addShape(s, { x: 870, y: 244, w: 230, h: 28, fill: C.red, line: ctx.line(C.red, 0) });
  metric(ctx, s, 860, 450, "<3s", "target detection window for live demo", C.mint);
  metric(ctx, s, 1040, 450, "64B", "fixed telemetry frame size", C.cyan);
}

function slideProblem(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 2);
  kicker(ctx, s, deck[1].kicker);
  title(ctx, s, deck[1].title, 92, 840);
  const threats = [
    ["PROCESS INJECTION", "Payload lives inside a trusted PID.", C.red],
    ["DKOM HIDING", "Kernel object exists, /proc view lies.", C.amber],
    ["SYSCALL HOOKING", "The sensor reads a modified truth.", C.violet],
    ["SLEEPING SHELLCODE", "Timing gaps hide bursts of behavior.", C.cyan],
  ];
  threats.forEach((t, i) => box(ctx, s, 80 + i * 292, 362, 250, 170, t[0], t[1], t[2]));
  ctx.addText(s, { x: 88, y: 584, w: 940, h: 40, text: "Judges should feel the pain instantly: normal tools can be right technically and still miss the compromise.", fontSize: 19, color: C.muted });
}

function slideCrossCheck(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 3);
  kicker(ctx, s, deck[2].kicker);
  title(ctx, s, deck[2].title, 92, 700);
  subtitle(ctx, s, deck[2].subtitle, 72, 236, 620);
  const cx = 875;
  const cy = 350;
  const items = [
    ["HOOK", 760, 190, C.cyan],
    ["eBPF", 960, 190, C.mint],
    ["/proc", 1040, 350, C.amber],
    ["MEM", 960, 510, C.red],
    ["GRAPH", 760, 510, C.violet],
  ];
  items.forEach(([label, x, y, color]) => {
    ctx.addShape(s, { x, y, w: 126, h: 74, fill: C.panel, line: ctx.line(color, 1.4) });
    ctx.addText(s, { x, y: y + 23, w: 126, h: 24, text: label, fontSize: 17, bold: true, color, typeface: ctx.fonts.mono, align: "center" });
    ctx.addShape(s, { x: Math.min(x + 63, cx), y: Math.min(y + 37, cy), w: Math.abs(cx - (x + 63)) || 2, h: 2, fill: C.line, line: ctx.line(C.line, 0) });
  });
  ctx.addShape(s, { x: cx - 88, y: cy - 88, w: 176, h: 176, geometry: "ellipse", fill: C.panel2, line: ctx.line(C.white, 1.2) });
  ctx.addText(s, { x: cx - 74, y: cy - 28, w: 148, h: 56, text: "CONTRADICTION SCORE", fontSize: 18, bold: true, color: C.text, typeface: ctx.fonts.mono, align: "center" });
}

function slideArchitecture(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 4);
  kicker(ctx, s, deck[3].kicker);
  title(ctx, s, deck[3].title, 84, 840);
  subtitle(ctx, s, deck[3].subtitle, 72, 212, 760);
  const nodes = [
    ["ASM / eBPF", "execve, mmap, mprotect, syscall timing", 80, 360, C.cyan],
    ["64B RING", "lock-free SPSC event frames", 335, 360, C.mint],
    ["GO GRAPH", "lineage, Welford rates, DKOM checks", 590, 360, C.amber],
    ["SCANNER", "AVX2 shellcode signature pass", 845, 360, C.red],
    ["TUI / SIEM", "operator view + signed webhooks", 1100, 360, C.violet],
  ];
  nodes.forEach(([a, b, x, y, color], i) => {
    box(ctx, s, x, y, 188, 126, a, b, color);
    if (i < nodes.length - 1) {
      ctx.addShape(s, { x: x + 198, y: y + 61, w: 50, h: 3, fill: C.line, line: ctx.line(C.line, 0) });
      ctx.addShape(s, { x: x + 244, y: y + 55, w: 12, h: 15, fill: color, line: ctx.line(color, 0) });
    }
  });
}

function slideSignals(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 5);
  kicker(ctx, s, deck[4].kicker);
  title(ctx, s, deck[4].title, 86, 780);
  subtitle(ctx, s, deck[4].subtitle, 72, 212, 650);
  const signals = [
    ["Orphan PID", 72, 350, 0.45, C.amber],
    ["Hollow proc", 72, 415, 0.78, C.red],
    ["Syscall spike", 72, 480, 0.64, C.cyan],
    ["DKOM mismatch", 72, 545, 0.9, C.violet],
    ["Timing gap", 72, 610, 0.56, C.mint],
  ];
  signals.forEach(([name, x, y, pct, color]) => {
    ctx.addText(s, { x, y: y - 10, w: 210, h: 24, text: name, fontSize: 16, color: C.text });
    ctx.addShape(s, { x: x + 230, y, w: 520, h: 14, fill: C.panel, line: ctx.line(C.panel, 0) });
    ctx.addShape(s, { x: x + 230, y, w: 520 * pct, h: 14, fill: color, line: ctx.line(color, 0) });
  });
  ctx.addShape(s, { x: 880, y: 334, w: 250, h: 250, geometry: "ellipse", fill: C.panel2, line: ctx.line(C.red, 2) });
  ctx.addText(s, { x: 918, y: 402, w: 174, h: 80, text: "91.3", fontSize: 62, bold: true, color: C.red, typeface: ctx.fonts.title, align: "center" });
  ctx.addText(s, { x: 918, y: 490, w: 174, h: 28, text: "CRITICAL SCORE", fontSize: 13, bold: true, color: C.muted, typeface: ctx.fonts.mono, align: "center" });
}

function slideMemoryScan(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 6);
  kicker(ctx, s, deck[5].kicker);
  title(ctx, s, deck[5].title, 90, 870);
  subtitle(ctx, s, deck[5].subtitle, 72, 226, 700);
  const rows = [
    ["0x7f10_0000", "r-xp anon", "NOP sled + syscall", "SHELLCODE"],
    ["0x7f12_4000", "r--p file", "clean", "IGNORE"],
    ["0x7f18_a000", "rwxp anon", "/bin/sh marker", "HIT"],
    ["0x7f22_c000", "r-xp anon", "beacon header", "HIT"],
  ];
  rows.forEach((r, i) => {
    const y = 344 + i * 58;
    const hit = r[3] !== "IGNORE";
    ctx.addShape(s, { x: 88, y, w: 1020, h: 42, fill: hit ? "#241622" : C.panel, line: ctx.line(hit ? C.red : C.line, 1) });
    r.forEach((cell, j) => {
      ctx.addText(s, { x: 110 + j * 245, y: y + 10, w: 220, h: 20, text: cell, fontSize: 14, color: hit && j === 3 ? C.red : C.text, typeface: j === 0 ? ctx.fonts.mono : ctx.fonts.body, bold: j === 3 });
    });
  });
  metric(ctx, s, 920, 226, "4x", "worker pool keeps scanning off the main event path", C.cyan);
}

function slideDemo(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 7);
  kicker(ctx, s, deck[6].kicker);
  title(ctx, s, deck[6].title, 88, 820);
  subtitle(ctx, s, deck[6].subtitle, 72, 218, 760);
  const steps = [
    ["00s", "sudo ghosttrace --mode=ebpf", C.cyan],
    ["08s", "launch benign exec-memory probe", C.amber],
    ["12s", "TUI alert turns CRITICAL", C.red],
    ["20s", "inspect lineage + export JSON", C.mint],
  ];
  steps.forEach(([time, label, color], i) => {
    const x = 96 + i * 285;
    ctx.addShape(s, { x, y: 390, w: 170, h: 170, geometry: "ellipse", fill: C.panel2, line: ctx.line(color, 2) });
    ctx.addText(s, { x: x + 35, y: 438, w: 100, h: 42, text: time, fontSize: 32, bold: true, color, typeface: ctx.fonts.mono, align: "center" });
    ctx.addText(s, { x: x - 10, y: 586, w: 190, h: 44, text: label, fontSize: 15, color: C.text, align: "center" });
    if (i < steps.length - 1) {
      ctx.addShape(s, { x: x + 180, y: 473, w: 92, h: 3, fill: C.line, line: ctx.line(C.line, 0) });
    }
  });
}

function slideWhyWins(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 8);
  kicker(ctx, s, deck[7].kicker);
  title(ctx, s, deck[7].title, 90, 840);
  const items = deck[7].bullets;
  items.forEach((item, i) => {
    const colors = [C.cyan, C.mint, C.amber, C.violet];
    box(ctx, s, 90 + (i % 2) * 550, 300 + Math.floor(i / 2) * 150, 470, 112, `PROOF ${i + 1}`, item, colors[i]);
  });
}

function slideRoadmap(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 9);
  kicker(ctx, s, deck[8].kicker);
  title(ctx, s, deck[8].title, 88, 850);
  subtitle(ctx, s, deck[8].subtitle, 72, 224, 700);
  const phases = [
    ["NOW", "single-host demo + signed alerts", C.cyan],
    ["NEXT", "incident replay + policy packs", C.mint],
    ["LATER", "fleet sensor + kernel module research", C.amber],
  ];
  phases.forEach(([phase, body, color], i) => {
    const x = 120 + i * 360;
    ctx.addShape(s, { x, y: 390, w: 300, h: 150, fill: C.panel, line: ctx.line(color, 1.5) });
    ctx.addText(s, { x: x + 24, y: 416, w: 220, h: 26, text: phase, fontSize: 15, bold: true, color, typeface: ctx.fonts.mono });
    ctx.addText(s, { x: x + 24, y: 460, w: 240, h: 54, text: body, fontSize: 21, color: C.text, typeface: ctx.fonts.title });
  });
}

function slideClose(p, ctx) {
  const s = p.slides.add();
  addBg(ctx, s, 10);
  kicker(ctx, s, deck[9].kicker);
  title(ctx, s, deck[9].title, 112, 980);
  subtitle(ctx, s, deck[9].subtitle, 72, 316, 780);
  ctx.addShape(s, { x: 72, y: 470, w: 500, h: 92, fill: C.panel2, line: ctx.line(C.cyan, 1.4) });
  ctx.addText(s, { x: 98, y: 500, w: 450, h: 32, text: "Judge it on speed, proof, and operator clarity.", fontSize: 24, bold: true, color: C.text, typeface: ctx.fonts.title });
  metric(ctx, s, 740, 458, "10", "slides built for a crisp 4-minute pitch", C.violet);
  metric(ctx, s, 940, 458, "1", "live demo that makes the idea real", C.mint);
}

main().catch((err) => {
  console.error(err.stack || err.message || String(err));
  process.exit(1);
});
