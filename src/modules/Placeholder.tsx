interface Props {
  title: string;
  milestone: string;
  items: string[];
}

export default function Placeholder({ title, milestone, items }: Props) {
  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">{title}</span>
          <span className="badge warn">{milestone}</span>
        </div>
        <div className="empty" style={{ textAlign: "left", lineHeight: 1.9 }}>
          该模块尚未实现，按里程碑逐个交付。计划能力：
          {items.map((it) => (
            <div key={it}>· {it}</div>
          ))}
        </div>
      </section>
    </div>
  );
}
