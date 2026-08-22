import { useEffect, useReducer, useState } from "react";

import { initialState, reduce } from "./reducer";
import type { WsMessage } from "./types";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/live";

export function useLive() {
  const [state, dispatch] = useReducer(reduce, initialState);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws: WebSocket;
    let retry: ReturnType<typeof setTimeout>;
    let closed = false;

    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 1000);
      };
      ws.onmessage = (msg) => {
        try {
          dispatch(JSON.parse(msg.data) as WsMessage);
        } catch {
          // ignore malformed frames
        }
      };
    };
    connect();

    return () => {
      closed = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  return { state, connected };
}
