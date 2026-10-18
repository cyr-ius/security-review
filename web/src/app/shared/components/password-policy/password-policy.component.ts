import { Component, computed, input } from '@angular/core';
import {
  MAX_PASSWORD_CHARS,
  MIN_PASSWORD_CHARS,
  PasswordRule,
  passwordRules,
} from '../../../core/constants/passwords';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Message of each rule of the password policy. */
const RULE_LABELS: Record<PasswordRule, MessageKey> = {
  length: 'password.length',
  lower: 'password.lower',
  upper: 'password.upper',
  digit: 'password.digit',
  symbol: 'password.symbol',
};

/**
 * Password policy shown while a new password is typed: each rule says whether it is met, and,
 * with a confirmation, whether it matches. Link the field to it with ``aria-describedby`` and
 * the ``id`` given here.
 */
@Component({
  selector: 'app-password-policy',
  imports: [TranslatePipe],
  templateUrl: './password-policy.component.html',
  styleUrl: './password-policy.component.css',
})
export class PasswordPolicyComponent {
  /** Id of the list of rules, for the aria-describedby of the password field. */
  readonly id = input.required<string>();
  readonly password = input.required<string>();
  /** Confirmation typed in another field; null: no confirmation field. */
  readonly confirmation = input<string | null>(null);

  readonly labels = RULE_LABELS;
  readonly min = MIN_PASSWORD_CHARS;
  readonly max = MAX_PASSWORD_CHARS;
  readonly rules = computed(() => passwordRules(this.password()));
  /** True or false once a confirmation is typed; null before. */
  readonly matches = computed(() => {
    const confirmation = this.confirmation();
    return confirmation ? confirmation === this.password() : null;
  });
}
