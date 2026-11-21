import type { SpeedSample } from "./api";

export function speedChart(samples: SpeedSample[]) {
  const valid = samples.filter((s) => Number.isFinite(Date.parse(s.at)) && Number.isFinite(s.up) && Number.isFinite(s.down) && s.up >= 0 && s.down >= 0).slice(-120);
  const end = valid.length ? Date.parse(valid[valid.length - 1].at) : 0;
  const recent = valid.filter((s) => Date.parse(s.at) >= end - 120000 && Date.parse(s.at) <= end);
  const peak = Math.max(1024, ...recent.flatMap((s) => [s.up, s.down]));
  const scale = 2 ** Math.ceil(Math.log2(peak));
  const line = (key: "up" | "down") => recent.map((s) => `${Math.max(0, Math.min(600, (Date.parse(s.at) - end + 120000) / 200))},${104 - s[key] / scale * 96}`).join(" ");
  return { up: line("up"), down: line("down"), scale, count: recent.length, current: recent[recent.length - 1] };
}
