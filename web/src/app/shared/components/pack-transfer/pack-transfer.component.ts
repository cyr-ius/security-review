import { Component, ElementRef, input, output, viewChild } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Largest TOML pack the server imports (standards.MAX_PACK_BYTES on the server). */
export const MAX_PACK_BYTES = 4 * 1024 * 1024;

/** A TOML file chosen by the user, read as text. */
export interface PackFile {
  name: string;
  content: string;
}

/** Why a chosen file was not read. */
export type PackFileError = 'tooLarge' | 'unreadable';

/**
 * Export and Import buttons of a TOML pack (rules, checklists or standards). The page calls
 * the API: this component only asks for the export and reads the chosen file.
 */
@Component({
  imports: [TranslatePipe],
  selector: 'app-pack-transfer',
  templateUrl: './pack-transfer.component.html',
  styleUrl: './pack-transfer.component.css',
})
export class PackTransferComponent {
  /** True while an export or an import runs: both buttons are disabled. */
  readonly busy = input(false);
  /** False for a user who may only read: the Import button is hidden. */
  readonly importable = input(true);
  readonly exportRequested = output<void>();
  readonly fileChosen = output<PackFile>();
  readonly fileRejected = output<PackFileError>();

  private readonly fileInput = viewChild.required<ElementRef<HTMLInputElement>>('fileInput');

  /** Open the file picker. */
  chooseFile(): void {
    this.fileInput().nativeElement.click();
  }

  /** Read the chosen file (bounded in size) and hand it to the page. */
  async onFileChange(event: Event): Promise<void> {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    // Reset the input so that choosing the same file again triggers a new import
    target.value = '';
    if (!file) {
      return;
    }
    if (file.size > MAX_PACK_BYTES) {
      this.fileRejected.emit('tooLarge');
      return;
    }
    try {
      this.fileChosen.emit({ name: file.name, content: await file.text() });
    } catch {
      this.fileRejected.emit('unreadable');
    }
  }
}
