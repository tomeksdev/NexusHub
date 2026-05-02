// MyConfigPage is the user-role landing page that lists the signed-in
// user's own peers + their .conf / QR exports. The current backend
// doesn't expose a `/me/peers` endpoint, so this is a placeholder
// surfacing what the page WILL do once the endpoint lands. Marked as
// stub-style intentionally — better than a broken fetch loop.
export function MyConfigPage() {
  return (
    <div className="space-y-4">
      <div className="topbar">
        <h1 className="page-title">My Config</h1>
      </div>
      <div className="panel">
        <p className="text-muted">
          A self-service view of your VPN configurations is coming. Until
          then, ask an admin for your <code>.conf</code> file or QR code.
        </p>
      </div>
    </div>
  );
}
