/** A small, CSS-only companion. Motion preferences are shared with the app. */
export function AsciiCat({ active = false }: { active?: boolean }) {
  return <pre className={`ascii-cat${active ? " ascii-cat--awake" : ""}`} aria-hidden="true">
    <span>{" /\\_/\\"}</span>
    <span>{"( "}<i className="ascii-cat__eye">o</i>{"."}<i className="ascii-cat__eye">o</i>{" )"}</span>
    <span>{" > ^ <"}</span>
  </pre>;
}
