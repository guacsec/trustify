import { test, expect, apiURL } from '../support';

test('affected and fixed verdicts, evidence, advisory links, and temporary resolution', async ({ page, seed, request }) => {
  await page.goto(`/correlation/${seed.belowFix}`);
  const row = page.getByRole('row').filter({ hasText: 'CVE-2022-4304' }).first();
  await expect(row).toContainText('Affected');
  await row.getByRole('button').first().click();
  await expect(page.getByRole('columnheader', { name: 'Extractor', exact: true })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Confidence', exact: true }).first()).toBeVisible();
  const advisory = page.getByRole('link').filter({ hasText: 'CVE-2022-4304' }).first();
  await expect(advisory).toBeVisible();
  await advisory.click();
  await expect(page.getByRole('heading', { name: /CVE-2022-4304/ }).first()).toBeVisible();
  await page.goBack();
  await row.getByRole('button').last().click();
  await page.getByRole('menuitem', { name: 'Explain verdict', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('Try temporary context')).toBeVisible();
  await dialog.getByText('Try temporary context').click();
  await dialog.getByRole('textbox', { name: 'Component provider (optional)' }).fill('e2e-preview-provider');
  const preview = page.waitForResponse(r => r.url().endsWith('/correlation/preview'));
  await dialog.getByRole('button', { name: 'Preview context', exact: true }).click();
  expect((await preview).ok()).toBeTruthy();
  await expect(dialog.getByRole('heading', { name: 'Temporary preview' }).first()).toBeVisible();
  await dialog.getByRole('button', { name: 'Close', exact: true }).last().click();
  // Preview must not persist its temporary provider or change the stored verdict.
  const result = await request.get(`${apiURL}/api/v3/correlation/sbom/${seed.belowFix}`);
  expect((await result.json()).verdicts.find((v: { vulnerability: { id: string } }) => v.vulnerability.id === 'CVE-2022-4304').status).toBe('affected');
  await page.goto(`/correlation/${seed.atFix}`);
  await expect(page.getByRole('row').filter({ hasText: 'CVE-2022-4304' }).first()).toContainText('Fixed');
});

test('unmatched components are shown without an affected verdict', async ({ page, seed }) => {
  await page.goto(`/correlation/${seed.patched}`);
  await expect(page.getByText('Unmatched components', { exact: false })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'urllib3' }).first()).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'CVE-2023-45803' })).toHaveCount(0);
});

for (const [kind, identifier] of [
  ['PURL', 'pkg:pypi/urllib3@1.26.17'],
  ['CPE', 'cpe:/o:redhat:enterprise_linux:8::baseos'],
]) {
  test(`${kind} identifier query reaches the real correlation API`, async ({ page, seed }) => {
    await page.goto('/query');
    await page.getByRole('button', { name: 'SKU', exact: true }).click();
    await page.getByRole('menuitem', { name: kind, exact: true }).click();
    await page.getByPlaceholder('Enter identifier value').fill(identifier);
    const pending = page.waitForResponse(r => r.url().includes('/api/v3/correlation/query?'));
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    const response = await pending;
    expect(response.ok(), await response.text()).toBeTruthy();
    const result = await response.json();
    expect(result.query.value).toBe(identifier);
    if (kind === 'PURL') {
      await expect(page.getByRole('row').filter({ hasText: 'CVE-2023-45803' }).first()).toContainText('Affected');
    } else {
      // A describing product CPE is not itself the vulnerable OpenSSL component.
      await expect(page.getByText(/No (verdicts|results|matches)/i).first()).toBeVisible();
    }
  });
}

test('match confidence documentation loads the server catalog', async ({ page, seed }) => {
  await page.goto('/confidence');
  await expect(page.getByRole('heading', { name: 'Match confidence', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Match method', exact: true })).toBeVisible();
  await expect(page.getByText(/not the probability/i)).toBeVisible();
});
