/**
 * Environment scrubbing for a cell.
 *
 * A cell starts from an explicit allowlist, not from the host environment.
 * Secrets never enter a cell by accident: API keys, tokens, cloud
 * credentials and npm/GitHub tokens are all dropped unless the user adds
 * one back explicitly with --env KEY=VALUE (an explicit, visible choice).
 *
 * HOME and TMPDIR are remapped into the cell directory, so $HOME-based
 * files (~/.ssh, ~/.config, ~/.npm) are out of reach. PATH is the one
 * host value we keep, because the cell needs a toolchain to run anything.
 */

export const ALLOWLIST = [
  "PATH",
  "TERM",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "USER",
  "LOGNAME",
] as const;

export interface ScrubbedEnv {
  env: Record<string, string>;
  droppedCount: number;
}

export function buildCellEnv(
  cellDir: string,
  cellId: string,
  network: string,
  envAdds: Record<string, string>,
  hostEnv: NodeJS.ProcessEnv = process.env,
): ScrubbedEnv {
  const env: Record<string, string> = {};
  let droppedCount = 0;

  for (const key of Object.keys(hostEnv)) {
    if ((ALLOWLIST as readonly string[]).includes(key)) {
      const value = hostEnv[key];
      if (value !== undefined) env[key] = value;
    } else {
      droppedCount++;
    }
  }

  // Remap HOME/TMPDIR into the cell so host dotfiles stay out of reach.
  env.HOME = cellDir;
  env.TMPDIR = cellDir;
  env.CELLRUN_CELL_ID = cellId;
  env.CELLRUN_NETWORK = network;

  // Explicit additions win over the allowlist (visible, deliberate).
  for (const [key, value] of Object.entries(envAdds)) {
    env[key] = value;
  }

  return { env, droppedCount };
}
