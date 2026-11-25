let trayHidden = false;
const trayChanges = new EventTarget();

export function setTrayHidden(hidden: boolean) {
  if (trayHidden === hidden) return;
  trayHidden = hidden;
  trayChanges.dispatchEvent(new Event("change"));
}

export function watchWindowActivity(change: (active: boolean) => void) {
  let active: boolean | undefined;
  const sync = () => {
    const next = !trayHidden && !document.hidden;
    if (next === active) return;
    active = next;
    change(next);
  };
  trayChanges.addEventListener("change", sync);
  document.addEventListener("visibilitychange", sync);
  sync();
  return () => {
    trayChanges.removeEventListener("change", sync);
    document.removeEventListener("visibilitychange", sync);
  };
}

export function startVisibleLoop(task: () => void | Promise<void>, delay: number | (() => number)) {
  let active = false, pending = false, resumed = false;
  let timer: number | undefined;
  const run = async () => {
    if (!active || pending) return;
    window.clearTimeout(timer);
    pending = true;
    try {
      await task();
    } finally {
      pending = false;
      if (active) {
        if (resumed) {
          resumed = false;
          void run();
        } else {
          timer = window.setTimeout(run, typeof delay === "number" ? delay : delay());
        }
      }
    }
  };
  const unwatch = watchWindowActivity((visible) => {
    active = visible;
    window.clearTimeout(timer);
    resumed = visible && pending;
    if (visible) void run();
  });
  return {
    run,
    stop: () => {
      active = false;
      window.clearTimeout(timer);
      unwatch();
    },
  };
}
