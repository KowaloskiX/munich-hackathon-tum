export type AppRoute = "home" | "network" | "phishing" | "mail";

const ROUTES = new Set<AppRoute>(["home", "network", "phishing", "mail"]);

export function routeFromHash(hash: string): AppRoute {
  const candidate = hash.replace(/^#\/?/, "").split("/")[0] || "home";
  return ROUTES.has(candidate as AppRoute) ? (candidate as AppRoute) : "home";
}

export function hashForRoute(route: AppRoute): string {
  return route === "home" ? "#/" : `#/${route}`;
}
