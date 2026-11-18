/** Decorative composition. It represents the product, never live project data. */
export function ThemeScene() {
  return <div className="theme-scene" aria-hidden="true"><svg viewBox="0 0 520 260" fill="none">
    <ellipse className="scene-shadow" cx="275" cy="227" rx="160" ry="13"/>
    <g className="scene-back"><rect x="203" y="30" width="240" height="152" rx="19"/><path d="M226 56h50M226 72h92M226 98h184M226 118h131M226 139h156"/></g>
    <g className="scene-link"><path d="M151 126h72q20 0 20-20V89h53M151 126h72q20 0 20 20v29h82"/><circle cx="296" cy="89" r="4"/><circle cx="325" cy="175" r="4"/></g>
    <g className="scene-front"><rect x="61" y="79" width="253" height="139" rx="21"/><path className="scene-divider" d="M61 113h253"/><circle cx="81" cy="97" r="3"/><circle cx="93" cy="97" r="3"/><circle cx="105" cy="97" r="3"/><rect className="scene-tile" x="82" y="133" width="54" height="60" rx="10"/><path className="scene-symbol" d="m95 152 14-8 14 8-14 8-14-8Zm0 10 14 8 14-8m-28 10 14 8 14-8"/><path d="M156 140h92M156 156h117M156 181h68"/><rect className="scene-action" x="251" y="176" width="39" height="20" rx="10"/></g>
    <g className="scene-orbit"><rect x="355" y="174" width="62" height="52" rx="15"/><path d="m374 199 9 9 15-18"/></g>
  </svg></div>;
}
