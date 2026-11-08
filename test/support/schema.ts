import type { RequestSchema } from '@asenajs/asena/adapter';

/** A Standard Schema v1 accepting an object whose `keys` all hold strings, so the tests need no schema library. */
export function stringFields<K extends string>(...keys: K[]): RequestSchema<unknown, Record<K, string>> {
  return {
    '~standard': {
      version: 1,
      vendor: 'asena-auth-test',
      validate: (value) => {
        const record = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
        const wrong = keys.filter((key) => typeof record[key] !== 'string');

        return wrong.length === 0
          ? { value: record as Record<K, string> }
          : { issues: wrong.map((key) => ({ message: `${key} must be a string`, path: [key] })) };
      },
    },
  };
}
