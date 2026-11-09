// #2463: a dialog busy with a request must not close on Escape.
//
// The Close case dialog disables Cancel while the close is on the wire (#2412), but the shared modal
// wiring closed every overlay on Escape regardless — so the dialog vanished mid-send and a later
// failure was written into a hidden dialog. A modal marked aria-busy="true" now swallows Escape.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { closeModal, isModalOpen, openModal } from "../../../public/js/a11y/modal.js";

type Listener = (ev: unknown) => void;

class FakeModal {
  private attrs = new Map<string, string>();
  private listeners: Listener[] = [];
  setAttribute(name: string, value: string): void {
    this.attrs.set(name, value);
  }
  getAttribute(name: string): string | null {
    return this.attrs.has(name) ? (this.attrs.get(name) as string) : null;
  }
  hasAttribute(name: string): boolean {
    return this.attrs.has(name);
  }
  removeAttribute(name: string): void {
    this.attrs.delete(name);
  }
  addEventListener(_type: string, fn: Listener): void {
    this.listeners.push(fn);
  }
  removeEventListener(_type: string, fn: Listener): void {
    this.listeners = this.listeners.filter((l) => l !== fn);
  }
  querySelector(): null {
    return null;
  }
  querySelectorAll(): never[] {
    return [];
  }
  focus(): void {}
  /** Dispatches Escape; returns whether something stopped its propagation. */
  pressEscape(): boolean {
    let stopped = false;
    const ev = { key: "Escape", stopPropagation: () => (stopped = true), preventDefault: () => {} };
    for (const l of [...this.listeners]) l(ev);
    return stopped;
  }
}

const g = globalThis as unknown as { document?: unknown };
let savedDocument: unknown;

beforeEach(() => {
  savedDocument = g.document;
  g.document = { activeElement: null, contains: () => false };
});

afterEach(() => {
  g.document = savedDocument;
});

function open() {
  const el = new FakeModal();
  const closed: string[] = [];
  const target = el as unknown as HTMLElement;
  openModal(target, { onClose: () => closed.push("closed") });
  return { el, target, closed };
}

describe("modal Escape while busy (#2463)", () => {
  it("Escape on a busy modal keeps it open and does not call onClose", () => {
    const { el, target, closed } = open();
    el.setAttribute("aria-busy", "true");
    expect(el.pressEscape()).toBe(true); // swallowed, not passed to the page
    expect(isModalOpen(target)).toBe(true);
    expect(closed).toEqual([]);
    closeModal(target);
  });

  it("Escape closes the modal again once it is no longer busy", () => {
    const { el, target, closed } = open();
    el.setAttribute("aria-busy", "true");
    el.pressEscape();
    el.removeAttribute("aria-busy");
    el.pressEscape();
    expect(isModalOpen(target)).toBe(false);
    expect(closed).toEqual(["closed"]);
  });

  it("Escape on a modal that was never busy closes it as before", () => {
    const { el, target, closed } = open();
    el.setAttribute("aria-busy", "false");
    el.pressEscape();
    expect(isModalOpen(target)).toBe(false);
    expect(closed).toEqual(["closed"]);
  });
});
