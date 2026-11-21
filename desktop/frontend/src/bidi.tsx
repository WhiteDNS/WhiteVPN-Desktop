import type { ReactNode } from "react";

// Latin words in a Persian sentence each get their own direction, so a list
// like "WebSocket، gRPC" keeps its order instead of reading back to front.
export function isolateLatin(text: string): ReactNode {
  return text.split(/([A-Za-z][A-Za-z0-9.+-]*)/).map((part, i) => (i % 2 ? <bdi key={i}>{part}</bdi> : part));
}
