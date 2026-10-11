import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ThemeService } from './core/services/theme.service';

/** Root component: applies the theme and hosts the routes. */
@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class App {
  // Instantiated here so that the theme is applied before the first page renders
  private readonly theme = inject(ThemeService);
}
