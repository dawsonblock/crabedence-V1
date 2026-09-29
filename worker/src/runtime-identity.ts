import type { Env } from "./types";

/**
 * The runtime identity of this deployment: the version file the commit was
 * built from and the exact deployed commit, both provided by the deploy
 * workflow. `/v1/health` publishes them so a running coordinator is never
 * identified by a version number alone — production tracks `main`, which
 * deploys ahead of releases.
 */
export function buildIdentity(env: Env): { version?: string; commit?: string } {
  const version = env.CRABBOX_BUILD_VERSION?.trim();
  const commit = env.CRABBOX_BUILD_COMMIT?.trim();
  return {
    ...(version ? { version } : {}),
    ...(commit ? { commit } : {}),
  };
}
