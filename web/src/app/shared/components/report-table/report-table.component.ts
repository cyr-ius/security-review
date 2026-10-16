import { DatePipe, SlicePipe } from '@angular/common';
import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { REVIEW_TYPE_META } from '../../../core/constants/labels';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ReportSummary } from '../../../core/models/api.models';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';

/** Table of reports, newest first. */
@Component({
  selector: 'app-report-table',
  imports: [RouterLink, DatePipe, SlicePipe, SeverityBadgeComponent, TranslatePipe],
  templateUrl: './report-table.component.html',
  styleUrl: './report-table.component.css',
})
export class ReportTableComponent {
  readonly reports = input.required<ReportSummary[]>();

  /** Hide the project column on a project page. */
  readonly showProject = input(true);

  readonly reviewTypeMeta = REVIEW_TYPE_META;
}
