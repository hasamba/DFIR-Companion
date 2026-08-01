// Hand-written declarations, matching the convention used by the other public/js modules
// (command-palette.d.ts, graph-view.d.ts). nextFocusIndex is the DOM-free half and is what the
// node-environment unit tests import; createFocusTrap is declared for completeness.
export declare function nextFocusIndex(count: number, current: number, backwards: boolean): number;
export declare function createFocusTrap(container: HTMLElement): {
  activate(): void;
  release(): void;
};
