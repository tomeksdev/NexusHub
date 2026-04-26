import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sseStream } from "./sse";

vi.mock("./api", () => ({
  // sseStream pulls the token through the api module; stub it so we don't
  // need to drag the refresh flow into SSE tests.
  getAccessTokenForStream: vi.fn(async () => "test-token"),
}));

// streamFromChunks builds a Response whose body yields each string as a
// separate chunk. That lets us verify the parser handles frame boundaries
// falling in the middle of a network chunk — the most common way a hand-
// rolled SSE parser breaks.
function streamFromChunks(chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(ctrl) {
      if (i >= chunks.length) {
        ctrl.close();
        return;
      }
      ctrl.enqueue(enc.encode(chunks[i++]));
    },
  });
}

function mockFetchWith(chunks: string[]) {
  const body = streamFromChunks(chunks);
  const resp = new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
  return vi.fn(async () => resp);
}

describe("sseStream", () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("dispatches event + data on blank-line terminator", async () => {
    globalThis.fetch = mockFetchWith([
      'event: peer\ndata: {"id":1}\n\n',
    ]) as unknown as typeof fetch;
    const events: Array<[string, string]> = [];
    await sseStream("/x", { onEvent: (e, d) => events.push([e, d]) });
    expect(events).toEqual([["peer", '{"id":1}']]);
  });

  it('defaults event name to "message" when none is sent', async () => {
    globalThis.fetch = mockFetchWith([
      "data: hello\n\n",
    ]) as unknown as typeof fetch;
    const events: Array<[string, string]> = [];
    await sseStream("/x", { onEvent: (e, d) => events.push([e, d]) });
    expect(events).toEqual([["message", "hello"]]);
  });

  it("concatenates multiple data lines with newlines", async () => {
    globalThis.fetch = mockFetchWith([
      "event: log\ndata: line one\ndata: line two\n\n",
    ]) as unknown as typeof fetch;
    const events: Array<[string, string]> = [];
    await sseStream("/x", { onEvent: (e, d) => events.push([e, d]) });
    expect(events).toEqual([["log", "line one\nline two"]]);
  });

  it("ignores comment lines that start with a colon", async () => {
    globalThis.fetch = mockFetchWith([
      ": keep-alive comment\nevent: peer\ndata: {}\n\n",
    ]) as unknown as typeof fetch;
    const events: Array<[string, string]> = [];
    await sseStream("/x", { onEvent: (e, d) => events.push([e, d]) });
    expect(events).toEqual([["peer", "{}"]]);
  });

  it("handles frames split across multiple chunks", async () => {
    // Worst case: event header in chunk A, data in chunk B, terminator in C.
    // A parser that dispatches on newline without buffering state across
    // chunks will leak fields into the next frame — this is the regression
    // this test is here to catch.
    globalThis.fetch = mockFetchWith([
      "event: peer\n",
      "data: ",
      '{"rx":1}\n\n',
    ]) as unknown as typeof fetch;
    const events: Array<[string, string]> = [];
    await sseStream("/x", { onEvent: (e, d) => events.push([e, d]) });
    expect(events).toEqual([["peer", '{"rx":1}']]);
  });

  it("passes the Authorization header from the token stub", async () => {
    const fetchSpy = mockFetchWith(["data: ok\n\n"]);
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    await sseStream("/x", { onEvent: () => {} });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const init = (fetchSpy.mock.calls[0] as unknown[])[1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer test-token");
    expect(headers.Accept).toBe("text/event-stream");
  });

  it("invokes onError + onClose on a non-ok response", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("nope", { status: 500 }),
    ) as unknown as typeof fetch;
    const onError = vi.fn();
    const onClose = vi.fn();
    await sseStream("/x", { onEvent: () => {}, onError, onClose });
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
