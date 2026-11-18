export type EcpLayoutNode = { id: string; x: number; y: number; width?: number; height?: number };

/** Deterministic bounded fallback layout for large DAGs; authority remains the server Flow. */
export function layoutEcpNodes(ids: string[], columns = 8): EcpLayoutNode[] {
  const width = 220, height = 72, gapX = 24, gapY = 18;
  return ids.map((id, index) => ({ id, x: (index % columns) * (width + gapX), y: Math.floor(index / columns) * (height + gapY), width, height }));
}
