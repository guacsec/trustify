import { test, expect, navigate } from '../support';

for (const [tool, key, value, field] of [
  ['cvss', 'vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Attack Vector'],
  ['purl', 'purl', 'pkg:maven/org.example/demo@1.0?classifier=sources#src/main', 'Canonical'],
  ['cpe', 'cpe', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', 'Normalized URI'],
]) {
  test(`${tool} supports deep links, validation, and clearing`, async ({ page, context }) => {
    await page.goto(`/tools/${tool}?${key}=${encodeURIComponent(value)}`);
    const input = page.getByRole('textbox');
    await expect(input).toHaveValue(value);
    await expect(page.getByText(field, { exact: true })).toBeVisible();
    await page.reload();
    await expect(input).toHaveValue(value);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.getByRole('button', { name: 'Copy link' }).click();
    await expect(page.getByRole('status')).toHaveText('Copied!');
    const shared = await page.evaluate(() => navigator.clipboard.readText());
    expect(new URL(shared).searchParams.get(key)).toBe(value);
    await page.goto('/tools/' + (tool === 'cpe' ? 'purl' : 'cpe'));
    await page.goBack();
    await expect(input).toHaveValue(value);
    await input.fill('invalid');
    await expect(page.locator('.pf-v6-c-alert').filter({ hasText: 'Invalid value' })).toBeVisible();
    await input.fill('');
    await expect(page.getByText('Enter a value to inspect it.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy link' })).toBeDisabled();
  });
}
test('Explore contains all inspection tools', async ({ page }) => {
  await page.goto('/');
  for (const name of ['CVSS', 'Package URL', 'CPE']) {
    await navigate(page, name);
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  }
});

for (const vector of [
  'AV:N/AC:L/Au:N/C:C/I:C/A:C',
  'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
]) {
  test(`CVSS detects ${vector.slice(0, 12)}`, async ({ page }) => {
    await page.goto(`/tools/cvss?vector=${encodeURIComponent(vector)}`);
    await expect(page.getByText('Base metrics', { exact: true })).toBeVisible();
    await expect(page.locator('.pf-v6-c-alert').filter({ hasText: 'Invalid value' })).toHaveCount(0);
  });
}
test('CPE distinguishes wildcard and NA attributes', async ({ page }) => {
  await page.goto('/tools/cpe?cpe=' + encodeURIComponent('cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*'));
  await expect(page.getByText('NA (-)', { exact: true })).toBeVisible();
  await expect(page.getByText('ANY (*)', { exact: true }).first()).toBeVisible();
});

for (const [tool, key, value] of [
  ['purl', 'purl', 'pkg:generic/demo@1.0?download_url=https%3A%2F%2Fexample.com%2Fa%3Fx%3D1%26y%3D2#src/main'],
  ['cpe', 'cpe', String.raw`cpe:2.3:a:foo\:bar:product:1.0:*:*:*:*:*:*:*`],
  ['cpe', 'cpe', 'cpe:/a:vendor:product:1.0'],
]) {
  test(`${tool} preserves escaped input ${value.slice(0, 35)}`, async ({ page }) => {
    await page.goto('/tools/' + tool);
    await page.getByRole('textbox').fill(value);
    await expect(page).toHaveURL(url => url.searchParams.get(key) === value);
    await page.reload();
    await expect(page.getByRole('textbox')).toHaveValue(value);
    await expect(page.locator('.pf-v6-c-alert').filter({ hasText: 'Invalid value' })).toHaveCount(0);
  });
}

test('inline advisory vectors link to their prefilled inspector', async ({ page, seed }) => {
  await page.goto('/advisory/' + seed.osv);
  await page.getByRole('button', { name: 'Overview', exact: true }).click();
  const link = page.getByTitle('Inspect CVSS').first();
  const vector = await link.textContent();
  await expect(link).toHaveAttribute('href', /tools\/cvss\?vector=/);
  await link.click();
  await expect(page.getByRole('textbox')).toHaveValue(vector!);
  await expect(page.getByText('Base metrics', { exact: true })).toBeVisible();
});

for (const [vector, score] of [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 'Base: 0.0 (None)'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'Base: 9.8 (Critical)'],
]) {
  test('CVSS detects severity for ' + score, async ({ page }) => {
    await page.goto('/tools/cvss?vector=' + encodeURIComponent(vector));
    await expect(page.getByText(score, { exact: true })).toBeVisible();
  });
}
