/** Shortest password of a web user accepted by the controller (web_users.MIN_PASSWORD_CHARS). */
export const MIN_PASSWORD_CHARS = 12;

/** Longest password accepted by the controller (web_users.MAX_PASSWORD_CHARS). */
export const MAX_PASSWORD_CHARS = 256;

/** A rule of the password policy of the controller (web_users.password_problems). */
export type PasswordRule = 'length' | 'lower' | 'upper' | 'digit' | 'symbol';

/** Tests of each rule, in the order they are shown; the controller checks them again. */
const PASSWORD_TESTS: readonly [PasswordRule, (value: string) => boolean][] = [
  ['length', (value) => value.length >= MIN_PASSWORD_CHARS && value.length <= MAX_PASSWORD_CHARS],
  ['lower', (value) => /\p{Ll}/u.test(value)],
  ['upper', (value) => /\p{Lu}/u.test(value)],
  ['digit', (value) => /\p{Nd}/u.test(value)],
  ['symbol', (value) => /[^\p{L}\p{N}]/u.test(value)],
];

/** Each rule of the password policy and whether ``value`` follows it. */
export function passwordRules(value: string): { rule: PasswordRule; ok: boolean }[] {
  return PASSWORD_TESTS.map(([rule, test]) => ({ rule, ok: test(value) }));
}

/** True when ``value`` follows every rule of the password policy. */
export function followsPasswordPolicy(value: string): boolean {
  return passwordRules(value).every((item) => item.ok);
}
