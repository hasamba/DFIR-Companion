// Finds every occurrence of many literal patterns in one pass over a text (Aho–Corasick). Built for
// "which of these thousands of IoC values appear in this event description": a separate
// `includes` per value is events × values scans, which pinned the server CPU on a real case.
// Build cost is the total pattern length; each search is linear in the text plus the matches.
// Case-sensitive over UTF-16 code units — lower-case both sides first for a case-insensitive match.

export class SubstringIndex {
  private readonly next: Map<number, number>[] = [new Map()];
  private readonly fail: number[] = [0];
  private readonly out: number[][] = [[]]; // patterns that end exactly at this node
  private readonly dictLink: number[] = [-1]; // nearest fail-ancestor that ends a pattern
  private readonly lengths: readonly number[];

  constructor(patterns: readonly string[]) {
    this.lengths = patterns.map((p) => p.length);
    patterns.forEach((p, idx) => {
      if (!p) return; // an empty pattern would "match" everywhere; callers never want that
      let s = 0;
      for (let k = 0; k < p.length; k++) {
        const c = p.charCodeAt(k);
        let n = this.next[s].get(c);
        if (n === undefined) {
          n = this.next.length;
          this.next.push(new Map());
          this.fail.push(0);
          this.out.push([]);
          this.dictLink.push(-1);
          this.next[s].set(c, n);
        }
        s = n;
      }
      this.out[s].push(idx);
    });
    this.linkFailures();
  }

  // Breadth-first, so every node's failure target (a shallower node) is final before it is used.
  private linkFailures(): void {
    const queue = [...this.next[0].values()]; // depth 1: fail to the root, no dictionary link
    for (let qi = 0; qi < queue.length; qi++) {
      const s = queue[qi];
      for (const [c, n] of this.next[s]) {
        let f = this.fail[s];
        while (f !== 0 && !this.next[f].has(c)) f = this.fail[f];
        const target = this.next[f].get(c) ?? 0;
        this.fail[n] = target;
        this.dictLink[n] = this.out[target].length > 0 ? target : this.dictLink[target];
        queue.push(n);
      }
    }
  }

  patternLength(pattern: number): number {
    return this.lengths[pattern];
  }

  /** Calls `visit(patternIndex, startOffset)` for every occurrence of every pattern in `text`. */
  forEachMatch(text: string, visit: (pattern: number, start: number) => void): void {
    let s = 0;
    for (let k = 0; k < text.length; k++) {
      const c = text.charCodeAt(k);
      let n = this.next[s].get(c);
      while (n === undefined && s !== 0) {
        s = this.fail[s];
        n = this.next[s].get(c);
      }
      s = n ?? 0;
      for (let o = this.out[s].length > 0 ? s : this.dictLink[s]; o > 0; o = this.dictLink[o]) {
        for (const p of this.out[o]) visit(p, k - this.lengths[p] + 1);
      }
    }
  }
}
