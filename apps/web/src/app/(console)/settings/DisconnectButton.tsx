"use client";

export function DisconnectButton() {
  return (
    <button className="secondary" onClick={async () => {
      await fetch("/api/session", { method: "DELETE" });
      window.location.href = "/connect";
    }}>
      Disconnect
    </button>
  );
}
