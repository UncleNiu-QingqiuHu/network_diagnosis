import { useEffect, useState } from "react";
import { licenseText } from "../lib/api";

export default function License() {
  const [text, setText] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    licenseText()
      .then(setText)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  if (err) return <div className="alert error">{err}</div>;

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">MIT License</span>
          <button
            className="btn"
            style={{ height: 26, padding: "0 10px", fontSize: 11 }}
            onClick={() => void navigator.clipboard.writeText(text)}
            type="button"
          >
            复制全文
          </button>
        </div>
        <p className="about-copy dim" style={{ marginBottom: 12 }}>
          允许商业使用、修改、分发与再授权，唯一义务是在副本中保留版权声明与本许可声明。软件按「现状」提供，不附带任何担保。
        </p>
        <pre className="pre" style={{ maxHeight: 460, whiteSpace: "pre-wrap", lineHeight: 1.75 }}>
          {text || "正在读取…"}
        </pre>
      </section>
    </div>
  );
}
