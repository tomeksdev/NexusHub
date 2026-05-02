interface Props {
  title: string;
  blurb: string;
}

export function StubPage({ title, blurb }: Props) {
  return (
    <div className="space-y-4">
      <div className="topbar">
        <h1 className="page-title">{title}</h1>
      </div>
      <div className="panel">
        <p className="text-muted">{blurb}</p>
      </div>
    </div>
  );
}
