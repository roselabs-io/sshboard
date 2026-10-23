const { test, expect } = require('@playwright/test');
const { execFileSync, spawn } = require('node:child_process');
const { once } = require('node:events');
const { mkdtemp, writeFile, mkdir, rm } = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

test('Inspect swaps the selected certificate into a dismissible, reopenable dialog', async ({ page, request }) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sshboard-browser-'));
  let server;
  try {
    const bin = path.join(dir, 'bin');
    await mkdir(bin);
    const sshboard = path.join(bin, 'sshboard');
    execFileSync('go', ['build', '-o', sshboard, '.'], { stdio: 'inherit' });
    await writeFile(path.join(bin, 'sshca'), `#!/bin/sh
if [ "$1" != cert ] || [ "$2" != inspect ]; then exit 1; fi
/bin/cat "$3"
`, { mode: 0o700 });
    const keyID = 'synthetic/repo@github-actions';
    const certificates = [
      { file: path.join(dir, 'first-cert.pub'), output: 'Synthetic certificate one\nSerial: 101\n' },
      { file: path.join(dir, 'second-cert.pub'), output: 'Synthetic certificate two\nSerial: 202\n' },
    ];
    for (const cert of certificates) await writeFile(cert.file, cert.output);
    await writeFile(path.join(dir, 'issuance-log.jsonl'), certificates.map(cert => JSON.stringify({
      ts: '2026-01-01T00:00:00Z', ca: 'user', key_id: keyID,
      principals: 'deploy-synthetic', valid: 'always', cert: cert.file,
    })).join('\n') + '\n');

    const listener = net.createServer();
    listener.listen(0, '127.0.0.1');
    await once(listener, 'listening');
    const port = listener.address().port;
    await new Promise(resolve => listener.close(resolve));
    const origin = `http://127.0.0.1:${port}`;
    server = spawn(sshboard, ['--bind', `127.0.0.1:${port}`, '--ca-dir', dir,
      '--config', path.join(dir, 'endpoints.yaml')], {
      env: { PATH: bin, HOME: dir }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let logs = '';
    server.stdout.on('data', data => { logs += data; });
    server.stderr.on('data', data => { logs += data; });
    await expect.poll(async () => {
      if (server.exitCode !== null) throw new Error(`sshboard exited: ${logs}`);
      try {
        return (await request.get(origin, { timeout: 1_000 })).status();
      } catch {
        return 0;
      }
    }, { timeout: 30_000 }).toBe(200);

    await page.goto(origin);
    await page.getByRole('link', { name: 'Certs', exact: true }).click();
    const certsURL = page.url();
    const rows = page.locator('#certs-deploy tbody tr');
    await expect(rows).toHaveCount(2);
    const dialog = page.locator('#cert-dialog dialog');
    for (const cert of [certificates[0], certificates[1], certificates[0]]) {
      const row = rows.filter({ has: page.locator(`input[name="cert"][value="${cert.file}"]`) });
      await row.getByRole('button', { name: 'Inspect', exact: true }).click();
      await expect(dialog).toHaveCount(1);
      await expect(dialog).toBeVisible();
      await expect(dialog.locator('header')).toHaveText(`Certificate ${keyID}`);
      await expect(dialog.locator('pre')).toHaveText(cert.output);
      await expect(page).toHaveURL(certsURL);
      await dialog.getByRole('button', { name: 'Close', exact: true }).click();
      await expect(dialog).not.toBeVisible();
    }
  } finally {
    if (server && server.exitCode === null) {
      const exited = once(server, 'close');
      server.kill();
      await exited;
    }
    await rm(dir, { recursive: true, force: true });
  }
});
