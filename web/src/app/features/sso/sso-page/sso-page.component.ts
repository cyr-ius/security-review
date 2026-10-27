import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { SsoSettingsComponent } from '../sso-settings/sso-settings.component';

/**
 * Administrator page for single sign-on: its settings, which override the SECREVIEW_OIDC_*
 * variables. What an OIDC user may do comes from the groups named by its groups claim (Groups
 * page).
 */
@Component({
  selector: 'app-sso-page',
  imports: [HelpLinkComponent, RouterLink, SsoSettingsComponent, TranslatePipe],
  templateUrl: './sso-page.component.html',
})
export class SsoPageComponent {}
