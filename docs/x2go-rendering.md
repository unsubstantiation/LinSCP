# Built-in X2Go rendering: current status

LinSCP wires an **experimental** built-in X2Go KDrive viewer through the
selected authenticated SSH tab. It lists resumable (`S`/`R`) server sessions,
starts a new agent or resumes an existing session, opens its graphics channel,
renders frames and server cursors, supports live window resizing (`resize`),
optional text clipboard sync (`Selection` / `DemandSelection` / `write_selection`),
explicit session suspend (`x2gosuspend-session`) or termination (`x2goterminate-session`),
and forwards keyboard/pointer input through a service bridge. Live-server validation
across diverse KDrive deployments remains required before removing the experimental
designation. NX3 and the former external NX launch path are not supported; a KDrive
server backend is required. Sound and X2Go server-side folder sharing are not
implemented.

## Decoded-frame surface

`ui/src/platform/desktop-frame-renderer.ts` accepts decoded RGBA pixel
rectangles and paints them on a canvas. It supports a full keyframe, ordered
incremental damage rectangles, dimension changes on a keyframe, stale frame
rejection, and resynchronization after a sequence gap. It bounds dimensions,
rectangle count, and per-frame data before allocating images. `remotePoint`
converts canvas-relative pointer positions back to remote pixel coordinates.
A new connection must reset the renderer and send a full keyframe before
sending deltas. This is an internal decoded-pixel contract, **not** the KDrive
wire protocol.

## KDrive wire decoder and handshake

`kdrive_wire::Decoder` incrementally frames TCP messages, including frames and
region references, cache deletions, cursors, selections, version and control
messages. It limits buffering, lengths, dimensions and counts, and permanently
fails closed on malformed/unknown messages. Image and clipboard payloads are
redacted from debug output. The parser exposes compressed region data; it does
not interpret cursor/clipboard content, UDP or rootless-window behavior.

The opt-in `x2go_transport::negotiate_kdrive` writes the 32-byte ASCII session
cookie and a client-version event over the provided SSH graphics channel, waits
for a server-version message with an overall timeout, and sends one-screen
geometry. It retains any subsequently received bytes in the decoder. Failure
closes the channel, but does **not** terminate the remote agent; callers must
provide reliable agent lifecycle cleanup. The guarded session uses it during startup.
It declares feature version 3 and Windows-style clipboard mode. Only server
feature versions 7 and 8 are accepted; other versions are refused conservatively
until compatibility is verified.
A negotiated channel can now be split into an ordered reader and independent
writer. The reader retains coalesced messages from the handshake and fails
closed on malformed data; writes are bounded by a timeout. The owner must drop
both halves after an error or interrupted write and separately terminate the
agent. `viewer_message` translates parsed frames, cache deletions, control
events (`Sync`, `Disconnect`), server cursors (`Cursor`, `DeletedCursors`), and
opt-in UTF-8 clipboard events (`Selection`, `DemandSelection`) to bounded viewer
JSON with base64 payloads; rootless-window and UDP messages are rejected. The
TypeScript IPC decoder validates and converts this contract before handing it
to `KDriveViewerSession`. The service has an `X2GoBridge` for an already
negotiated, guarded channel: it validates input, resize (`resize`), and
clipboard (`write_selection`) packets, tracks live wire frame-cache IDs and
evictions via `WireFrameTracker` + `FrameCache::apply_deleted_frames` (failing
closed on unknown cached frame references), preserves output order, applies
bounded backpressure, and supports explicit session suspend (`x2gosuspend-session`)
or termination (`x2goterminate-session`) as well as best-effort cleanup on closure. The service
can associate a bridge with the exact connected SSH tab and exposes nonblocking
poll, input, and close routes. Closing or reconnecting a tab releases its bridge;
an abandoned viewer lease expires after 60 seconds. Explicit suspend keeps the
output receiver alive until the actor processes the suspend command, even when
the output queue is full or the requesting API future is cancelled. It reports
an error rather than claiming suspension when the bridge already terminated.
This only protects the local lifecycle ordering; a broken SSH connection or
server-side failure can still leave the remote session's state unknown. The experimental X2Go
open route registers that bridge and the page polls it, forwards input, and
requests close. Poll, input and close carry a service-issued generation so
delayed requests from an earlier viewer cannot operate on a replacement bridge.
This generation is not an authentication credential. The bridge sends protocol keepalives and closes on prolonged server silence
while it is able to read. Linux and Windows CI run the service's X2Go-focused
unit tests; they use synthetic graphics streams and do not establish live-server compatibility.

Wire-layout facts were researched from the public GPL-3.0
[Casement KDrive client](https://github.com/Inkbraid/casement-plugin-x2go)
and its documented behavior; this is an independent implementation, with no
third-party source or captured test data copied into the project. Tests use
synthetic packets. Actual server compatibility, version assumptions, partial
I/O, and teardown still need live X2Go verification.

`ui/src/platform/kdrive-image-decoder.ts` decodes JPEG/PNG regions using the
WebView's `createImageBitmap` and canvas APIs. It checks encoded size and
header dimensions before invoking the decoder and checks decoded dimensions
again, serializes calls, and frees temporary image/canvas resources. The shared
`KDriveFramePipeline` now connects this decoder to `DesktopFrameRenderer`: it
composes compressed regions and cached references, applies deletions, clips
screen updates, and invalidates the cache and screen on errors. It bounds cache,
image, encoded data and composition work, and rejects overlapping calls; its
caller must deliver wire messages in order and explicitly reset after an error.
It rejects rootless-window frames rather than pretending to support them. Tests
use synthetic frames and a simulated WebView; its IPC path is wired to the Rust
wire parser but has not been tested against a live session. WebView support, malicious image handling and
color behavior must be tested on Linux, Windows and macOS. Native image-library
behavior cannot be proven safe solely by header checks.

## Decoded-image cache

`crates/linscp-proto/src/desktop_frame_cache.rs` is a protocol-independent,
bounded cache of tightly packed decoded RGBA images. It can build a new image
from ordered pixel patches and rectangular copies of previous entries, with
explicit removal and reset. It rejects missing entries, invalid rectangles,
incorrect lengths and resource-limit violations atomically; it does not evict
entries implicitly. Cached screen pixels are redacted in debug output.

The implementation caps stored pixels at 256 MiB and 4096 entries, each image
at 8192 pixels per dimension and 16,777,216 total pixels, and composition work
at four output images or 128 MiB (whichever is smaller). Building a replacement
can temporarily allocate one additional image (up to 64 MiB), in addition to
caller-owned decoded pixels and allocator/hash-table overhead. Callers must
select lower limits as needed and bound input before decoding. These are LinSCP
safety limits, not negotiated KDrive limits: real protocol compatibility and
how to recover after a limit or cache miss remain to be determined. In the
backend bridge (`crates/linscp-service/src/x2go_bridge.rs`), `WireFrameTracker`
uses `FrameCache::apply_deleted_frames` and metadata tracking to validate cached
region references and evictions on the incoming KDrive wire stream, while
`FrameCache::compose_wire_rgba_frame` supports decoded RGBA region composition.

## Input capture

`ui/src/platform/kdrive-events.ts` encodes fixed-size key, button, motion and
update-request packets with checked fields. A key press is not equivalent to
blindly forwarding a DOM keydown; the server handles modifier masks and key
strokes differently. Packet layouts are based on the public KDrive client linked
above; tests use synthetic data. Live server behavior remains unverified.

`KDriveInputQueue` serializes translator actions, copies packets, bounds queued
work, and waits at barriers after sending a one-pixel update request. The
page uses a one-pixel response heuristic to acknowledge it;
this protocol has no unique request identifier, so correlation with unsolicited
one-pixel updates must be tested and handled conservatively. A timeout, write
failure, overflow or close stops the queue and the owning session must close
its SSH graphics stream. The queue cannot cancel a write already in progress.
It is tested with fake writers and is not connected to a live session.

`KDriveViewerSession` ties the frame pipeline, renderer, input capture,
translator and queue together behind an injected transport. It serializes and
bounds parsed incoming messages, enables input only after a main image, and
closes on overflow, decode errors or disconnect. A supplied transport must write
packets, request a new main image on reinitialization, and arrange remote agent
cleanup; the reader delivers messages and uses a heuristic to identify barrier replies.
Tests exercise this wiring with a simulated transport and WebView. The page
uses `/api/x2go/open`, poll, input and close; it has not been tested against an
actual X2Go server. Generic desktop launch/ticket requests still reject X2Go.

`DesktopInput` captures keyboard, mouse buttons, motion and wheel events on the
focused canvas, and releases held keys and buttons on focus loss or teardown.
It starts disabled. `KDriveInputTranslator` now maps common browser physical
keys to XKB evdev keycodes and creates KDrive packets, tracks modifiers and
locks, and emits required ordering barriers. The caller must serialize all
input actions and perform a real server round trip for each barrier before
sending later actions; the input queue above provides that ordering once a
session connects its writer and barrier-response reader. The translator requires explicit initial remote lock
states and AltGr configuration; unsupported keys, IME, horizontal scrolling and
Windows' synthetic Ctrl preceding AltGr are not handled. It is connected to
the SSH bridge but has not been tested with a live viewer. On transport failure the backend must
reset its remote key/button state; local synthetic releases cannot guarantee
that a disconnected peer receives them.

## NX implementation investigation

The [ArcticaProject nx-libs source](https://github.com/ArcticaProject/nx-libs/tree/58d42b6edf3b08c34878448ca0153cede91463cf)
contains NX compression (`nxcomp`) and `nxproxy`, rather than a WebView-ready
RGBA decoder. Its [NXCOMP license](https://github.com/ArcticaProject/nx-libs/blob/58d42b6edf3b08c34878448ca0153cede91463cf/LICENSE.nxcomp)
is GPL version 2 only. LinSCP's own `LICENSE` is PolyForm Noncommercial. Before
linking, modifying, or distributing those components with LinSCP, their license
compatibility and distribution requirements need review; this is not a legal
conclusion. The nx-libs README also describes embedding nxproxy in another
window as pending, so bundling it alone would not provide this canvas renderer.
Linux, Windows and macOS build and display-server support remain unverified.
No nx-libs code or binaries have been added to this project.

An important constraint for an independent implementation: NX3 compresses and
caches **X11 protocol traffic**, rather than streaming a framebuffer. Decoding
NX traffic alone does not produce RGBA rectangles; a client also needs an X11
server or equivalent implementation of the X11 drawing protocol to produce
pixels and process input. See [NX architecture](https://www.linuxjournal.com/article/8489)
and the [X2Go KDrive developer discussion](https://lists.x2go.org/pipermail/x2go-dev/2018-December/012945.html).
No complete wire-format specification or independently licensed compatible NX3
decoder has been identified in this investigation. Neither a handshake nor a
decoder has been implemented or verified here.

X2Go KDrive is a separate server-side X2Go graphics backend that transmits
framebuffer updates and does not require an X server on the client. It is not
NX3 and requires additional server software; supporting it would not make an
ordinary X2Go/NX server work without that backend. See the
[upstream KDrive overview](https://www.mail-archive.com/x2go-commits@lists.x2go.org/msg23022.html).
The user has selected investigating KDrive and permits dropping NX support; this
is not authorization to install server packages without an explicit action.

### KDrive findings

- On Debian, the KDrive integration is provided by `x2goserver-x2gokdrive`,
  which depends on `xserver-x2gokdrive`; `x2goserver` and
  `x2goserver-xsession` are also needed for the session. Package availability
  varies by release and repository. Debian trixie lists
  `xserver-x2gokdrive` 0.0.0.3; Ubuntu 24.04 lists 0.0.0.2 in Universe.
  See the [Debian package metadata](https://packages.debian.org/trixie/x2goserver-x2gokdrive),
  [Debian versions](https://packages.debian.org/search?keywords=xserver-x2gokdrive),
  [Ubuntu versions](https://packages.ubuntu.com/xserver-x2gokdrive), and the
  [Ubuntu 20.04 dependency report](https://bugs.x2go.org/cgi-bin/bugreport.cgi?bug=1607).
  The server probe checks `x2gostartagent`, `x2gokdrive` and the X2Go KDrive
  integration version file under `/usr/share/x2go/versions`. It is only a
  presence check: it does not verify the backend version, endianness, SSH TCP
  forwarding, permissions or live compatibility, and custom installation paths
  may be reported missing. The reviewed, opt-in installer requests the KDrive
  packages from existing Debian/Ubuntu and Fedora/RHEL repositories; other
  distributions must set them up manually. Package resolution can still fail.
  No repository or desktop is added automatically; XFCE remains a separate opt-in.
- [An independently written KDrive client](https://github.com/Inkbraid/casement-plugin-x2go)
  documents starting a `K` session, carrying the graphics port through the
  same SSH connection, a cookie handshake, JPEG/PNG frame updates and caching,
  input events, and lifecycle handling. Its implementation is GPL-3.0; no code
  or captured test data has been copied into LinSCP. Its Windows-specific
  implementation and claimed tests are useful evidence, not proof that this
  project supports Linux, Windows, or macOS.
- The viewer delivers parsed frame, cursor, and opt-in clipboard messages to
  the frame pipeline, translates browser input and window resize events, and
  coordinates session listing, resume, suspend, termination, and transport
  lifecycle; live server integration tests remain required across distributions.
  UDP and rootless-window support are not present.
- A [public KDrive client release announcement](https://www.mail-archive.com/x2go-announcements@lists.x2go.org/msg00217.html)
  mentions version negotiation before requesting the main image and geometry
  updates to elicit an initial image. It does not provide a complete message
  layout. The independent wire framing implementation described above uses
  protocol-layout facts from the other public client reference.

An X2Go session also has to be started or resumed on the server before graphics
can flow. The [x2gostartagent manual](https://github.com/eugenesan/x2goserver/blob/master/x2goserver/man/man8/x2gostartagent.8)
describes required session parameters and returned graphics connection details.
Starting an agent without a functioning decoder and reliable teardown can
leave a remote session running without a usable viewer. The experimental X2Go
open route uses the guarded startup primitive in `x2go_control`:
it runs the restricted startup command on the existing SSH connection, validates
the reply and immediately creates a cleanup guard. A cancelled caller leaves
startup running so the resulting guard can attempt cleanup. A guarded graphics
session can also launch a fixed XFCE, MATE or LXDE command after negotiation;
the background command's exit status does not prove the desktop started.
The guard attempts bounded termination over the same SSH connection on close,
setup failure, or drop. Cleanup on drop is best-effort: runtime shutdown,
process termination, a broken SSH connection, or an invalid/lost startup reply
can still leave an agent behind. The cookie is redacted in debug output and
zeroized when the parsed session is dropped. These primitives are wired into
the service and tested with synthetic responses, not live servers.
Startup replies and command behavior still need verification against live X2Go
servers.

`x2go_transport::open_graphics_stream` can open the validated agent's graphics
port on the destination's loopback through an already-authenticated SSH
connection. The caller must use the same destination connection that created
the agent; it never falls back to direct TCP. The handshake and wire decoder
are connected to the experimental viewer through the service bridge.
Opening or dropping the stream does not start or terminate an agent. The SSH
mock integration tests use an echo server, not X2Go.

## Still required for a verified viewer

- Compile and run Rust tests and verify startup, rendering, input, and cleanup
  against actual KDrive servers on supported client platforms.
- Verify compatibility of server versions, frame and cursor semantics, keyboard
  barriers, and WebView image decoding. The one-pixel barrier has no request ID
  and can be confused with an unsolicited update.
- Add robust recovery for failed startup replies, lifecycle failures and
  reconnects; cleanup remains best-effort after timeouts or lost SSH.
- Support a resizable separate desktop window, resizing, cursor, clipboard,
  optional sound, and session resume as distinct features. None is promised by
  this experimental fixed-size in-page viewer.
