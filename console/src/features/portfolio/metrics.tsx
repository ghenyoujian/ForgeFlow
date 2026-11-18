import { useEffect, useState } from "react";
import { CircleHelp, MoveHorizontal } from "lucide-react";
import { num, object } from "./monitor";

export function UnknownMetric({ description }: { description: string }) {
  return (
    <span
      className="unknown-metric"
      role="note"
      tabIndex={0}
      title={description}
      aria-label={`未提供：${description}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        color: "var(--muted)",
      }}
    >
      —<CircleHelp size={12} aria-hidden="true" />
    </span>
  );
}
export function ProgressMetric({
  value,
  description,
}: {
  value: unknown;
  description: string;
}) {
  const progress = object(value);
  const numerator = num(
    progress.numerator ?? progress.completed ?? progress.passed,
  );
  const denominator = num(
    progress.denominator ?? progress.total ?? progress.required,
  );
  if (numerator === undefined || denominator === undefined)
    return <UnknownMetric description={description} />;
  return (
    <span
      title={`${description}；分子 ${numerator}，分母 ${denominator}${denominator === 0 ? "，没有验收对象，不计算百分比" : ""}`}
    >
      {numerator} / {denominator}
    </span>
  );
}

export function TableScrollHint() {
  const [narrow, setNarrow] = useState(
    () => window.matchMedia("(max-width: 767px)").matches,
  );
  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const changed = () => setNarrow(media.matches);
    media.addEventListener("change", changed);
    return () => media.removeEventListener("change", changed);
  }, []);
  if (!narrow) return null;
  return (
    <p
      className="muted"
      style={{ display: "flex", alignItems: "center", gap: 6 }}
    >
      <MoveHorizontal size={14} aria-hidden="true" />
      左右滑动查看完整列，点选对象查看详情。
    </p>
  );
}
