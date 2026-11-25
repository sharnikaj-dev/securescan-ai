import React, { useState } from "react";
import { ArrowLeft, Eye, EyeOff, Lock, ShieldCheck } from "lucide-react";
import { api, setAuthToken } from "../lib/api";
import { UserProfile } from "../types";

interface AuthViewProps {
  initialMode: "login" | "register";
  onBackToLanding: () => void;
  onAuthenticated: (user: UserProfile) => void;
}

export function AuthView({
  initialMode,
  onBackToLanding,
  onAuthenticated,
}: AuthViewProps) {
  const [mode, setMode] = useState<"login" | "register">(initialMode);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organization, setOrganization] = useState("");
  const [role, setRole] = useState("Security Engineer");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanEmail = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }
    if (mode === "register" && name.trim().length < 2) {
      setError("Please enter your full name (at least 2 characters).");
      return;
    }

    setLoading(true);
    try {
      const res =
        mode === "register"
          ? await api.register({
              name: name.trim(),
              email: cleanEmail,
              password,
              organization: organization.trim() || "Independent",
              role: role.trim() || "Security Engineer",
            })
          : await api.login({ email: cleanEmail, password });

      setAuthToken(res.token);
      onAuthenticated(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#FAF6ED] dark:bg-[#101712] text-[#1B2B20] dark:text-[#F5F1E6] flex flex-col">
      <header className="border-b border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7]/90 dark:bg-[#141E17]/90 px-6 h-16 flex items-center justify-between">
        <button
          type="button"
          onClick={onBackToLanding}
          className="inline-flex items-center gap-2 text-sm font-medium text-[#4A5E4E] dark:text-[#C4D3BF] hover:text-[#3D6A39] dark:hover:text-[#A5D190] cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to SecureScan AI</span>
        </button>
        <span className="text-xs text-[#617565] dark:text-[#98AD94]">
          Encrypted scrypt Authentication
        </span>
      </header>

      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-md rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-lg bg-[#E7F1DC] dark:bg-[#223326] border border-[#C3D6B1] dark:border-[#2A3D30] flex items-center justify-center text-[#3D6A39] dark:text-[#A5D190]">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
                {mode === "login" ? "Sign in to SecureScan AI" : "Create your security account"}
              </h1>
              <p className="text-xs text-[#617565] dark:text-[#98AD94]">
                Access your static analysis console and scan history
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-[#EEF5E6] dark:bg-[#0D130F] border border-[#D5E2C8] dark:border-[#2A3D30] mb-6">
            <button
              type="button"
              onClick={() => {
                setMode("login");
                setError(null);
              }}
              className={`py-2 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                mode === "login"
                  ? "bg-[#FFFDF7] dark:bg-[#223326] text-[#1B2B20] dark:text-[#F5F1E6] border border-[#D5E2C8] dark:border-[#2A3D30]"
                  : "text-[#4A5E4E] dark:text-[#98AD94] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("register");
                setError(null);
              }}
              className={`py-2 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                mode === "register"
                  ? "bg-[#FFFDF7] dark:bg-[#223326] text-[#1B2B20] dark:text-[#F5F1E6] border border-[#D5E2C8] dark:border-[#2A3D30]"
                  : "text-[#4A5E4E] dark:text-[#98AD94] hover:text-[#1B2B20] dark:hover:text-[#F5F1E6]"
              }`}
            >
              Create Account
            </button>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-5 p-3 rounded-lg border border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === "register" && (
              <>
                <div>
                  <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                    Full Name
                  </label>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Alex Mercer"
                    className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                      Organization
                    </label>
                    <input
                      type="text"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      placeholder="Acme Security"
                      className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                      Role
                    </label>
                    <input
                      type="text"
                      value={role}
                      onChange={(e) => setRole(e.target.value)}
                      placeholder="AppSec Lead"
                      className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Work Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="engineer@company.com"
                className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Minimum 8 characters"
                  className="w-full px-3.5 py-2.5 pr-10 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#617565] hover:text-[#1B2B20] dark:text-[#98AD94] dark:hover:text-[#F5F1E6] cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] disabled:opacity-60 rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
            >
              <Lock className="w-4 h-4" />
              <span>
                {loading
                  ? "Authenticating..."
                  : mode === "login"
                  ? "Sign In to Console"
                  : "Create Account"}
              </span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
