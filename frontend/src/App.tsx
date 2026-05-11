import { useState } from "react";
import {
  Activity,
  AlertCircle,
  BarChart3,
  Gauge,
  HelpCircle,
  KeyRound,
  Layers,
  LogOut,
  MapPin,
  Settings,
  ShieldAlert,
  Smartphone,
  UserCircle,
  Users,
} from "lucide-react";

import { Logo } from "./components/Logo";
import { useAuth } from "./lib/auth";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { InterfacesPage as LocationsPage } from "./pages/InterfacesPage";
import { LoginPage } from "./pages/LoginPage";
import { MetricsPage } from "./pages/MetricsPage";
import { MyConfigPage } from "./pages/MyConfigPage";
import { PeersPage } from "./pages/PeersPage";
import { ProfilePage } from "./pages/ProfilePage";
import { RulesPage } from "./pages/RulesPage";
import { StubPage } from "./pages/StubPage";
import { SupportPage } from "./pages/SupportPage";
import { UserDetailPage } from "./pages/UserDetailPage";
import { UsersPage } from "./pages/UsersPage";

type Page =
  // admin
  | "dashboard"
  | "locations"
  | "users"
  | "monitoring"
  | "global_config"
  | "groups"
  | "access_rules"
  | "ebpf_rules"
  | "audit"
  | "profile"
  | "support"
  // user
  | "my_config"
  | "my_monitoring";

interface NavEntry {
  id: Page;
  label: string;
  icon: typeof Activity;
}

interface NavSection {
  title: string;
  items: NavEntry[];
}

const ADMIN_NAV: NavSection[] = [
  {
    title: "Main",
    items: [
      { id: "dashboard", label: "Dashboard", icon: Gauge },
      { id: "locations", label: "Locations", icon: MapPin },
      { id: "users", label: "Users", icon: Users },
      { id: "monitoring", label: "Monitoring", icon: BarChart3 },
    ],
  },
  {
    title: "Configuration",
    items: [
      { id: "global_config", label: "Global Config", icon: Settings },
      { id: "groups", label: "Groups", icon: Layers },
      { id: "access_rules", label: "Access Rules", icon: ShieldAlert },
    ],
  },
  {
    title: "Security",
    items: [
      { id: "ebpf_rules", label: "eBPF Rules", icon: KeyRound },
      { id: "audit", label: "Audit Log", icon: AlertCircle },
    ],
  },
  {
    title: "Profile",
    items: [
      { id: "profile", label: "My Profile", icon: UserCircle },
      { id: "support", label: "Support", icon: HelpCircle },
    ],
  },
];

// USER_NAV — sidebar for the `user` role. Monitoring is admin-only
// (the /metrics endpoint requires admin); exposing it as a sidebar
// entry that immediately 403s was a worse experience than not
// showing it at all. Restore if/when there's a user-scoped metrics
// view.
const USER_NAV: NavSection[] = [
  {
    title: "Main",
    items: [{ id: "my_config", label: "My Config", icon: Smartphone }],
  },
  {
    title: "Profile",
    items: [
      { id: "profile", label: "My Profile", icon: UserCircle },
      { id: "support", label: "Support", icon: HelpCircle },
    ],
  },
];

function App() {
  const { isAuthenticated, role, email, signOut } = useAuth();
  const isAdmin = role === "admin" || role === "super_admin";
  const sections = isAdmin ? ADMIN_NAV : USER_NAV;
  const defaultPage: Page = isAdmin ? "dashboard" : "my_config";
  const [page, setPage] = useState<Page>(defaultPage);
  // Drilling into a user record swaps the main pane to UserDetailPage
  // without touching the sidebar selection. Setting back to null
  // returns to the Users list.
  const [selectedUserID, setSelectedUserID] = useState<string | null>(null);

  if (!isAuthenticated) return <LoginPage />;

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar">
        <div className="sidebar-brand">
          {/* Single horizontal row: icon + wordmark. Subtitle on its
              own line below, smaller, so the logo+name read as the
              primary brand element. The current /logo.png has a
              tiny bit of embedded text — replace it with an
              icon-only PNG before tagging (see public/README.md). */}
          <div className="flex items-center gap-2.5">
            <Logo size={28} />
            <h1>NexusHub</h1>
          </div>
          <p className="mt-1">WireGuard control plane</p>
        </div>
        <nav aria-label="Primary" className="flex-1 py-2">
          {sections.map((section) => (
            <div className="sidebar-section" key={section.title}>
              <span className="sidebar-section-title">{section.title}</span>
              {section.items.map((entry) => {
                const Icon = entry.icon;
                const active = page === entry.id;
                return (
                  <button
                    key={entry.id}
                    type="button"
                    onClick={() => {
                      setPage(entry.id);
                      // Leaving the Users area implicitly closes any
                      // open detail view.
                      if (entry.id !== "users") setSelectedUserID(null);
                    }}
                    aria-current={active ? "page" : undefined}
                    className={"nav-item" + (active ? " active" : "")}
                  >
                    <span className="nav-icon">
                      <Icon size={16} />
                    </span>
                    <span>{entry.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-row">
            <span className="status-dot" aria-hidden />
            <span>System healthy</span>
          </div>
          <div title={email ?? ""} className="truncate">
            {email}
          </div>
          <button
            type="button"
            onClick={signOut}
            className="mt-2 inline-flex items-center gap-2 text-muted hover:text-white text-xs"
          >
            <LogOut size={14} /> Sign out
          </button>
        </div>
      </aside>

      <main id="main-content" tabIndex={-1} className="main-content">
        {renderPage(page, isAdmin, selectedUserID, setSelectedUserID)}
      </main>
    </div>
  );
}

function renderPage(
  page: Page,
  isAdmin: boolean,
  selectedUserID: string | null,
  setSelectedUserID: (id: string | null) => void,
) {
  if (isAdmin) {
    switch (page) {
      case "dashboard":
        return <DashboardPage />;
      case "locations":
        return <LocationsPage />;
      case "users":
        return selectedUserID ? (
          <UserDetailPage
            userID={selectedUserID}
            onBack={() => setSelectedUserID(null)}
          />
        ) : (
          <UsersPage onOpen={(id) => setSelectedUserID(id)} />
        );
      case "monitoring":
        return <MetricsPage />;
      case "ebpf_rules":
        return <RulesPage />;
      case "audit":
        return <AuditPage />;
      case "profile":
        return <ProfilePage />;
      case "support":
        return <SupportPage />;
      case "global_config":
        return (
          <StubPage
            title="Global Config"
            blurb="App-wide settings (default DNS, SMTP, feature flags) ship in v2.1. Today these live in env vars."
          />
        );
      case "groups":
        return (
          <StubPage
            title="Groups"
            blurb="Group-based assignment of users + locations is part of the v2.1 access-control rollout."
          />
        );
      case "access_rules":
        return (
          <StubPage
            title="Access Rules"
            blurb="Priority-ordered allow/deny rules per group/location/user — coming with the access-control rollout in v2.1."
          />
        );
      // Peers list intentionally lives under Locations as a per-location
      // detail view; the standalone admin page is reachable via the
      // table row click. Keep an alias for now.
      default:
        return <PeersPage />;
    }
  }
  switch (page) {
    case "my_config":
      return <MyConfigPage />;
    case "my_monitoring":
      return <MetricsPage />;
    case "profile":
      return <ProfilePage />;
    case "support":
      return <SupportPage />;
    default:
      return <MyConfigPage />;
  }
}

export default App;
