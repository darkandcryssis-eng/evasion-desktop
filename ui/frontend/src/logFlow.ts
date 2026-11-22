// The journal behind the session window keeps its place while the Home screen is away: switching tabs must not start it over.
export type FlowRow = { id: number; text: string };
export type Flow = { session: string; rows: FlowRow[]; cursor: number; at: number };

export const STEP = 1500;
// Enough rows to reach past the top of the window, so the oldest line is dropped out of sight.
export const ROWS = 24;
const OPENING = 6;

export const emptyFlow = (session = ""): Flow => ({ session, rows: [], cursor: 0, at: 0 });

// New lines enter at the bottom; the oldest leave above the frame.
export function advance(flow: Flow, lines: string[], now: number, count = 1): Flow {
  if (!lines.length || count < 1) return flow;
  let { rows, cursor } = flow;
  for (let n = 0; n < count; n++) rows = [...rows.slice(-ROWS), { id: cursor, text: lines[cursor++ % lines.length] }];
  return { ...flow, rows, cursor, at: now };
}

// A new session opens with a few lines; a returning screen gets the lines that passed while it was away.
export function resume(flow: Flow, session: string, lines: string[], now: number): Flow {
  if (flow.session !== session || !flow.rows.length) return advance(emptyFlow(session), lines, now, OPENING);
  return advance(flow, lines, now, Math.min(ROWS + 1, Math.floor((now - flow.at) / STEP)));
}
