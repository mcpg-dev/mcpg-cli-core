//! SSE phase-ladder rendering for provisioning streams.
//!
//! The CP's publish/delete endpoints respond with a Server-Sent-Events
//! stream of phase events (allocating → applying → ready). This renders
//! each event as one human line, surfacing the instance coordinates the
//! moment they appear.

/// Drain an SSE response, printing each `event:` line and its
/// associated `data:` JSON. Returns when the stream closes.
/// Stops printing transient bytes — only the parsed event/phase
/// pairs reach stdout.
pub async fn stream_phases(resp: reqwest::Response) -> anyhow::Result<()> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.extend_from_slice(&chunk);
        // Process complete event blocks (separated by \n\n).
        while let Some(pos) = find_double_newline(&buf) {
            let block = buf[..pos].to_vec();
            buf.drain(..pos + 2);
            if let Ok(s) = std::str::from_utf8(&block) {
                print_block(s);
            }
        }
    }
    if !buf.is_empty()
        && let Ok(s) = std::str::from_utf8(&buf)
    {
        print_block(s);
    }
    Ok(())
}

fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n")
}

fn print_block(block: &str) {
    let mut event = "";
    let mut data: Option<&str> = None;
    for line in block.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            event = rest;
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data = Some(rest);
        }
    }
    if event.is_empty() || matches!(event, "ping" | "keep-alive") {
        return;
    }
    let parsed = data.and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok());
    let summary = parsed
        .as_ref()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_default();
    if summary.is_empty() {
        println!("  ▸ {event}");
    } else {
        println!("  ▸ {event}: {summary}");
    }
    // Surface the instance coordinates the moment an event carries them —
    // the endpoint URL is THE thing a user needs from a publish (it's what
    // they paste into their MCP client), and the uid is what delete takes.
    if let Some(coords) = parsed.as_ref().and_then(|v| v.get("coords"))
        && !coords.is_null()
    {
        if let Some(uid) = coords.get("instance_uid").and_then(|u| u.as_str()) {
            println!("      instance_uid: {uid}");
        }
        if let Some(eps) = coords.get("endpoints").and_then(|e| e.as_array()) {
            for ep in eps.iter().filter_map(|e| e.as_str()) {
                println!("      endpoint:     {ep}   ← point your MCP client here");
            }
        }
    }
}
