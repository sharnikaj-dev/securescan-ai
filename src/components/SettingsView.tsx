import React, { useEffect, useState } from "react";
import { CheckCircle2, Moon, Server, Sun, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { SeverityLevel, ThemeMode, UserProfile } from "../types";

interface SettingsViewProps {
  user: UserProfile;
  theme: ThemeMode;
  onUserUpdated: (user: UserProfile) => void;
  onThemeChange: (theme: ThemeMode) => void;
  onAccountDeleted: () => void;
}

export function SettingsView({
  user,
  theme,
  onUserUpdated,
  onThemeChange,
  onAccountDeleted,
}: SettingsViewProps) {
  const [name, setName] = useState(user.name);
  const [organization, setOrganization] = useState(user.organization);
  const [role, setRole] = useState(user.role);
  const [defaultLanguage, setDefaultLanguage] = useState(user.scanPreferences.defaultLanguage);
  const [minSeverity, setMinSeverity] = useState<SeverityLevel>(user.scanPreferences.minSeverity);
  const [autoAiSummary, setAutoAiSummary] = useState(user.scanPreferences.autoAiSummary);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [healthInfo, setHealthInfo] = useState<{
    geminiConfigured: boolean;
    database: string;
  } | null>(null);

  useEffect(() => {
    void api
      .health()
      .then((res) =>
        setHealthInfo({ geminiConfigured: res.geminiConfigured, database: res.database })
      )
      .catch(() => {});
  }, []);

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedMsg(null);
    setError(null);
    try {
      const res = await api.updateProfile({
        name: name.trim(),
        organization: organization.trim(),
        role: role.trim(),
        themePreference: theme,
        scanPreferences: {
          defaultLanguage,
          minSeverity,
          autoAiSummary,
        },
        ...(newPassword ? { currentPassword, newPassword } : {}),
      });
      onUserUpdated(res.user);
      setCurrentPassword("");
      setNewPassword("");
      setSavedMsg("Profile and scan preferences saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteAccount = async () => {
    setDeleting(true);
    try {
      await api.deleteAccount();
      onAccountDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete account.");
      setDeleting(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#1B2B20] dark:text-[#F5F1E6] font-display">
          Settings &amp; User Profile
        </h1>
        <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
          Manage your account credentials, interface theme, and static analysis defaults.
        </p>
      </div>

      {savedMsg && (
        <div className="p-3.5 rounded-lg border border-emerald-500/40 bg-emerald-50 dark:bg-emerald-950/30 text-xs text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{savedMsg}</span>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="p-3.5 rounded-lg border border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/30 text-xs text-red-700 dark:text-red-300"
        >
          {error}
        </div>
      )}

      <form onSubmit={handleSaveProfile} className="space-y-6">
        <section className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-4">
          <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
            Engineer Profile
          </h2>

          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Full Name
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Email Address
              </label>
              <input
                type="email"
                disabled
                value={user.email}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30]/70 bg-[#EEF5E6] dark:bg-[#0D130F]/60 text-[#617565] dark:text-[#98AD94]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Organization
              </label>
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Security Role
              </label>
              <input
                type="text"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              />
            </div>
          </div>
        </section>

        <section className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-5">
          <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
            Appearance &amp; Scan Preferences
          </h2>

          <div>
            <p className="text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-2">
              Interface Theme
            </p>
            <div className="inline-flex p-1 rounded-lg bg-[#EEF5E6] dark:bg-[#0D130F] border border-[#D5E2C8] dark:border-[#2A3D30]">
              <button
                type="button"
                onClick={() => onThemeChange("light")}
                className={`inline-flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-md cursor-pointer transition-colors ${
                  theme === "light"
                    ? "bg-[#9BC585] text-[#142617]"
                    : "text-[#4A5E4E] dark:text-[#98AD94]"
                }`}
              >
                <Sun className="w-3.5 h-3.5" />
                <span>Cream &amp; Pista</span>
              </button>
              <button
                type="button"
                onClick={() => onThemeChange("dark")}
                className={`inline-flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-md cursor-pointer transition-colors ${
                  theme === "dark"
                    ? "bg-[#9BC585] text-[#142617]"
                    : "text-[#4A5E4E] dark:text-[#98AD94]"
                }`}
              >
                <Moon className="w-3.5 h-3.5" />
                <span>Deep Pistachio</span>
              </button>
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Default Target Language
              </label>
              <select
                value={defaultLanguage}
                onChange={(e) => setDefaultLanguage(e.target.value)}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              >
                {[
                  "Auto-Detect",
                  "Python",
                  "JavaScript",
                  "TypeScript",
                  "Java",
                  "PHP",
                  "C",
                  "C++",
                ].map((lang) => (
                  <option key={lang} value={lang}>
                    {lang}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Minimum Reported Severity
              </label>
              <select
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] focus:outline-none focus:border-[#6A9E58]"
              >
                <option value="low">Low &amp; Above</option>
                <option value="medium">Medium &amp; Above</option>
                <option value="high">High &amp; Critical Only</option>
                <option value="critical">Critical Only</option>
              </select>
            </div>
          </div>

          <label className="flex items-center gap-2.5 text-xs text-[#4A5E4E] dark:text-[#C4D3BF] cursor-pointer">
            <input
              type="checkbox"
              checked={autoAiSummary}
              onChange={(e) => setAutoAiSummary(e.target.checked)}
              className="rounded border-[#C3D6B1] dark:border-[#2A3D30] accent-[#6A9E58]"
            />
            <span>Prioritize Gemini AI remediation prompts for newly opened scan reports</span>
          </label>
        </section>

        <section className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-3">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-[#3D6A39] dark:text-[#A5D190]" />
            <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
              Server Runtime &amp; API Configuration
            </h2>
          </div>
          <p className="text-xs text-[#4A5E4E] dark:text-[#C4D3BF] leading-relaxed">
            Gemini API credentials and database connection settings are managed strictly via
            server-side environment variables and never exposed to the browser.
          </p>
          <div className="grid sm:grid-cols-2 gap-3 pt-1 text-xs">
            <div className="p-3 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
              <p className="text-[#617565] dark:text-[#98AD94]">Gemini AI Service</p>
              <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mt-0.5">
                {healthInfo?.geminiConfigured
                  ? "Configured (gemini-4-hydrogen)"
                  : "Awaiting GEMINI_API_KEY in server secrets"}
              </p>
            </div>
            <div className="p-3 rounded-lg border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F]">
              <p className="text-[#617565] dark:text-[#98AD94]">Persistence Layer</p>
              <p className="font-semibold text-[#1B2B20] dark:text-[#F5F1E6] mt-0.5">
                SQLite Active · PostgreSQL Schema Ready
              </p>
            </div>
          </div>
        </section>

        <section className="p-6 rounded-xl border border-[#D5E2C8] dark:border-[#2A3D30] bg-[#FFFDF7] dark:bg-[#17221B] space-y-4">
          <h2 className="text-sm font-semibold text-[#1B2B20] dark:text-[#F5F1E6]">
            Update Password (Optional)
          </h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                Current Password
              </label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Required to change password"
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] mb-1.5">
                New Password
              </label>
              <input
                type="password"
                minLength={8}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                className="w-full px-3.5 py-2 text-sm rounded-lg border border-[#C3D6B1] dark:border-[#2A3D30] bg-[#FAF6ED] dark:bg-[#0D130F] text-[#1B2B20] dark:text-[#F5F1E6] placeholder:text-[#617565]/70 focus:outline-none focus:border-[#6A9E58]"
              />
            </div>
          </div>
        </section>

        <div className="flex items-center justify-end">
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 text-sm font-semibold text-[#142617] bg-[#9BC585] hover:bg-[#8AB773] disabled:opacity-60 rounded-lg transition-colors cursor-pointer"
          >
            {saving ? "Saving Changes..." : "Save Settings"}
          </button>
        </div>
      </form>

      <section className="p-6 rounded-xl border border-red-300/70 dark:border-red-500/30 bg-[#FFFDF7] dark:bg-[#17221B] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-red-600 dark:text-red-400">
            Delete Account &amp; Scan History
          </h2>
          <p className="text-xs text-[#617565] dark:text-[#98AD94] mt-1">
            Permanently remove your user profile, active sessions, and all stored vulnerability reports.
          </p>
        </div>

        {!confirmDelete ? (
          <button
            type="button"
            onClick={() => setConfirmDelete(true)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-red-600 dark:text-red-400 border border-red-400/50 hover:bg-red-500/10 rounded-lg shrink-0 cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Delete Account</span>
          </button>
        ) : (
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setConfirmDelete(false)}
              className="px-3 py-2 text-xs font-medium text-[#4A5E4E] dark:text-[#C4D3BF] border border-[#C3D6B1] dark:border-[#2A3D30] rounded-lg cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={deleting}
              onClick={handleDeleteAccount}
              className="px-3 py-2 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg cursor-pointer"
            >
              {deleting ? "Deleting..." : "Confirm Permanent Delete"}
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
