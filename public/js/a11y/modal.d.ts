// Hand-written declarations, matching the convention used by the other public/js modules.
// Every export here is DOM-bound, so the behavior is covered in a real browser by
// companion/tests/e2e/a11y/keyboard.spec.ts rather than by node unit tests.
export declare function openModal(
  el: HTMLElement,
  opts?: { labelledBy?: string; describedBy?: string; onClose?: () => void },
): void;
export declare function closeModal(el: HTMLElement): void;
export declare function isModalOpen(el: HTMLElement): boolean;
