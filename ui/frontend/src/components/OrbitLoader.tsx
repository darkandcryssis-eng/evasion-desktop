const ticks = Array.from({ length: 24 }, (_, i) => i);

export function OrbitLoader({ className = "" }: { className?: string }) {
  return (
    <svg className={`orbit-loader ${className}`.trim()} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      {ticks.map((i) => <path key={i} d="M32 4v7" transform={`rotate(${i * 15} 32 32)`} style={{ animationDelay: `${-i * .06}s` }} />)}
    </svg>
  );
}
