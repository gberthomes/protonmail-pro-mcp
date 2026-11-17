/**
 * Integration with a REAL official Proton Mail Bridge — disabled by default.
 *
 *   BRIDGE_IT_SETTINGS_DIR=/path/to/.config/protonmail/bridge-v3 npm test
 *
 * Read-only: inspects the instance, lists accounts, attaches to the event
 * stream and detaches, then checks Bridge is still running. It never signs in
 * or touches accounts; real-account checks are done manually with the CLI
 * (see docs/bridge-manager.md, "Validation with real accounts").
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { BridgeClient } from '../src/bridge-manager/client.js';
import { inspectInstance } from '../src/bridge-manager/instance.js';
import { BridgeManager } from '../src/bridge-manager/manager.js';

const settingsDir = process.env.BRIDGE_IT_SETTINGS_DIR;

describe('real Proton Mail Bridge (opt-in)', { skip: settingsDir ? false : 'set BRIDGE_IT_SETTINGS_DIR to run' }, () => {
  it('is reachable, tested, and keeps running after the Manager detaches', async () => {
    const report = await inspectInstance({ id: 'it', settingsDir: settingsDir! }, { checkBinary: false });
    assert.equal(report.running, true, JSON.stringify(report.problems));
    assert.equal(report.compat.level, 'tested', report.compat.detail);
    assert.ok(report.keychain?.current, 'Bridge has a keychain');

    const manager = new BridgeManager([{ id: 'it', settingsDir: settingsDir! }]);
    const events: string[] = [];
    await manager.onEvents('it', e => events.push(`${e.kind}:${'type' in e ? e.type : ''}`));
    const accounts = await manager.accounts('it');
    assert.ok(Array.isArray(accounts));
    assert.ok(accounts.every(a => a.id && a.username && !('password' in a)));
    await new Promise(r => setTimeout(r, 1000));
    await manager.close();

    // Bridge quits if its event stream is cut without StopEventStream: it must still answer.
    await new Promise(r => setTimeout(r, 1000));
    const again = await BridgeClient.connect(settingsDir!);
    assert.equal(await again.version(), report.version);
    await again.close();
  });
});
