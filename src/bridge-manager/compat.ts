/**
 * Compatibility matrix for the internal gRPC interface of Proton Mail Bridge.
 *
 * The interface is private to Proton (used by bridge-gui) and can change in
 * any release. Read-only operations are allowed on any 3.x release; operations
 * that change state (sign-in, sign-out, removal) are refused on versions that
 * were not tested, unless the operator explicitly opts in.
 */

export interface CompatEntry {
  version: string;
  status: 'tested' | 'known-compatible';
  notes: string;
}

export const COMPATIBILITY: CompatEntry[] = [
  {
    version: '3.27.2',
    status: 'tested',
    notes: 'Interface reviewed against the official source; read-only calls and event stream verified against the signed Linux package.'
  }
];

export type CompatLevel = 'tested' | 'untested' | 'unsupported';

function parse(version: string): [number, number, number] | undefined {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
}

export function compatibility(version: string | undefined): { level: CompatLevel; detail: string } {
  if (!version) return { level: 'unsupported', detail: 'Bridge version unknown' };
  const v = parse(version);
  if (!v) return { level: 'unsupported', detail: `Unrecognised Bridge version "${version}"` };
  if (v[0] !== 3) return { level: 'unsupported', detail: `Bridge ${version}: only the 3.x series is supported` };
  const entry = COMPATIBILITY.find(e => e.version === `${v[0]}.${v[1]}.${v[2]}`);
  if (entry) return { level: 'tested', detail: `Bridge ${version}: ${entry.status}` };
  return { level: 'untested', detail: `Bridge ${version} has not been tested with this Manager (tested: ${COMPATIBILITY.map(e => e.version).join(', ')})` };
}

/** Throws unless state-changing operations are allowed for this version. */
export function assertWritable(version: string | undefined, allowUntested: boolean): void {
  const c = compatibility(version);
  if (c.level === 'tested') return;
  if (c.level === 'untested' && allowUntested) return;
  throw new Error(
    `${c.detail}. Refusing a state-changing operation${c.level === 'untested' ? ' (set BRIDGE_MANAGER_ALLOW_UNTESTED=true to override at your own risk)' : ''}.`
  );
}
