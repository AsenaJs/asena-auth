import { $ } from 'bun';
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';

const ROOT = `${import.meta.dir}/..`;

const manifest = (await Bun.file(`${ROOT}/package.json`).json()) as {
  name: string;
  exports: Record<string, Record<string, string>>;
};

let workDir: string;
let packageDir: string;
let packedFiles: string[];

beforeAll(async () => {
  workDir = (await $`mktemp -d`.text()).trim();
  packageDir = `${workDir}/package`;

  await $`mkdir ${packageDir}`;
  await $`cp package.json README.md LICENSE ${packageDir}/`.cwd(ROOT);
  await $`${ROOT}/node_modules/.bin/tsc -p tsconfig.json --outDir ${packageDir}/dist`.cwd(ROOT);

  const packOutput = await $`bun pm pack --dry-run 2>&1`.cwd(packageDir).text();

  packedFiles = packOutput
    .split('\n')
    .map((line) => /^packed \S+ (.+)$/.exec(line.trim())?.[1])
    .filter((path): path is string => path !== undefined);
});

afterAll(async () => {
  await $`rm -rf ${workDir}`;
});

describe('published tarball', () => {
  test('packs the build output', () => {
    expect(packedFiles).toContain('dist/index.js');
  });

  test('contains nothing from the test tree', () => {
    expect(packedFiles.filter((path) => path.split('/').includes('test'))).toEqual([]);
  });

  test('contains every file the exports map points at', () => {
    const targets = Object.values(manifest.exports).flatMap((conditions) =>
      Object.values(conditions).map((target) => target.replace(/^\.\//, '')),
    );

    expect(targets).toContain('dist/testing.js');
    expect(packedFiles).toEqual(expect.arrayContaining(targets));
  });

  test('the ./testing subpath resolves for a consumer', async () => {
    const consumerDir = `${workDir}/consumer`;

    await $`mkdir -p ${consumerDir}/node_modules/@asenajs`;
    await $`ln -s ${packageDir} ${consumerDir}/node_modules/${manifest.name}`;

    expect(Bun.resolveSync(`${manifest.name}/testing`, consumerDir)).toBe(`${packageDir}/dist/testing.js`);
  });
});
