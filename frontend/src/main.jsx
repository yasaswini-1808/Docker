import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = (import.meta.env.VITE_API_URL || "http://localhost:5000/api").replace(/\/$/, "");

function App() {
  const [page, setPage] = useState(window.location.pathname === "/verify" ? "verify" : "register");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [otp, setOtp] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [verified, setVerified] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("authToken") || "");

  useEffect(() => {
    if (window.location.pathname === "/verify") setPage("verify");
    if (token) {
      fetch(`${API}/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
        .then(async r => ({ ok: r.ok, data: await r.json() }))
        .then(({ ok, data }) => {
          if (ok) setUser(data.user);
          else { localStorage.removeItem("authToken"); setToken(""); }
        }).catch(() => {});
    }
  }, []);

  async function submit(event) {
    event.preventDefault();
    setBusy(true); setMessage(""); setError("");
    const endpoint = page === "register" ? "register" : "login";
    const body = page === "register" ? form : { email: form.email, password: form.password };
    try {
      const response = await fetch(`${API}/auth/${endpoint}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Request failed.");
      if (page === "register") {
        setMessage(`${data.message} Open Mailpit to view the code.`);
        setPage("verify");
        setVerified(false);
        window.history.pushState({}, "", "/verify");
      } else {
        localStorage.setItem("authToken", data.token);
        setToken(data.token); setUser(data.user); setMessage(data.message);
      }
    } catch (e) { setError(e.message || "Unable to connect to the server."); }
    finally { setBusy(false); }
  }

  async function verify() {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(`${API}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.email, otp })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Verification failed.");
      setMessage(data.message);
      setVerified(true);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  function logout() {
    localStorage.removeItem("authToken"); setToken(""); setUser(null);
    setForm({ name: "", email: "", password: "" }); setMessage("You have logged out.");
    setPage("login");
  }

  if (user) return <main className="shell"><section className="card">
    <div className="brand-mark">✓</div><h1>Welcome, {user.name}!</h1>
    <p className="subtitle">Your email is verified and you are logged in.</p>
    <div className="profile"><span>Name</span><strong>{user.name}</strong><span>Email</span><strong>{user.email}</strong><span>Status</span><strong className="verified">Verified</strong></div>
    <button onClick={logout}>Log out</button>
  </section></main>;

  if (page === "verify") return <main className="shell"><section className="card">
    <div className="brand-mark">✉</div><h1>Verify your email</h1>
    <p className="subtitle">Enter the 6-digit OTP sent to your email address.</p>
    {message && <div className="notice success">{message}</div>}
    {error && <div className="notice error">{error}</div>}
    {!verified && <form onSubmit={event => { event.preventDefault(); verify(); }}>
      <label>Email address<input type="email" required maxLength="254" value={form.email} onChange={e => setForm({...form, email:e.target.value})} placeholder="you@example.com" /></label>
      <label>Verification OTP<input inputMode="numeric" pattern="[0-9]{6}" required maxLength="6" value={otp} onChange={e => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="6-digit code" /></label>
      <button type="submit" disabled={busy}>{busy ? "Verifying..." : "Verify email address"}</button>
    </form>}
    <p className="switch">Already verified? <a href="/" onClick={e => { e.preventDefault(); setPage("login"); window.history.pushState({}, "", "/"); setMessage(""); setError(""); }}>Log in</a></p>
  </section></main>;

  return <main className="shell"><section className="card">
    <div className="brand-mark">U</div>
    <p className="eyebrow">SECURE ACCOUNT</p>
    <h1>{page === "register" ? "Create your account" : "Welcome back"}</h1>
    <p className="subtitle">{page === "register" ? "Register and verify your email to get started." : "Log in with your verified email address."}</p>
    <div className="tabs">
      <button className={page === "register" ? "tab active" : "tab"} onClick={() => {setPage("register");setMessage("");setError("");}}>Register</button>
      <button className={page === "login" ? "tab active" : "tab"} onClick={() => {setPage("login");setMessage("");setError("");}}>Log in</button>
    </div>
    <form onSubmit={submit}>
      {page === "register" && <label>Full name<input autoComplete="name" required minLength="2" maxLength="120" value={form.name} onChange={e => setForm({...form, name:e.target.value})} placeholder="Your full name" /></label>}
      <label>Email address<input type="email" autoComplete="email" required maxLength="254" value={form.email} onChange={e => setForm({...form, email:e.target.value})} placeholder="you@example.com" /></label>
      <label>Password<input type="password" autoComplete={page === "register" ? "new-password" : "current-password"} required minLength="8" maxLength="72" value={form.password} onChange={e => setForm({...form, password:e.target.value})} placeholder="At least 8 characters" /></label>
      {message && <div className="notice success">{message}</div>}
      {error && <div className="notice error">{error}</div>}
      <button type="submit" disabled={busy}>{busy ? "Please wait..." : page === "register" ? "Create account" : "Log in"}</button>
    </form>
    {page === "register" && <p className="fineprint">A 6-digit verification OTP will be sent to your email. It expires after 15 minutes.</p>}
    <p className="mailpit">Development email inbox: <a href="http://localhost:8025" target="_blank" rel="noreferrer">Open Mailpit ↗</a></p>
  </section><p className="footer">React · Express · PostgreSQL · Redis · Docker</p></main>;
}

createRoot(document.getElementById("root")).render(<App />);
