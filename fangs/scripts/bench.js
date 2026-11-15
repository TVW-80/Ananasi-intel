// Runs the measurement suites (replay P/R, nDCG, latency, layout) and prints the numbers. Results land in results/*.json.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const r = spawnSync(process.execPath, ['--test', '--test-concurrency=1', 'test/replay.test.js', 'test/dispatch.test.js', 'test/perf.test.js'], { cwd: root, stdio: 'inherit' });
process.exit(r.status ?? 1);
