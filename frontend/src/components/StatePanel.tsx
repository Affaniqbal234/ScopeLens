export function StatePanel({
  title,
  detail,
  tone = "plain",
}: {
  title: string;
  detail?: string;
  tone?: "plain" | "error";
}) {
  return (
    <div
      className={`state-panel state-panel--${tone}`}
      role={tone === "error" ? "alert" : "status"}
    >
      <strong>{title}</strong>
      {detail && <p>{detail}</p>}
    </div>
  );
}
