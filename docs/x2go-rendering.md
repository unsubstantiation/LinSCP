# Built-in X2Go rendering: current status

LinSCP does **not** yet have a built-in X2Go viewer. The intended implementation
is now **KDrive**, not NX3; the user has accepted dropping NX compatibility.
The former external NX client launch path has been removed. X2Go launch and
ticket requests now report that the built-in viewer is not implemented; no
remote agent is started. The shared `DesktopFrameRenderer` is only a building
block; it is not connected to `/api/desktop/launch` and must not be advertised
as a working viewer.

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
provide reliable agent lifecycle cleanup. The function is not wired to launch.
It declares feature version 3 and Windows-style clipboard mode; clipboard
handling is not implemented. Only server feature versions 7 and 8 are accepted;
other versions are refused conservatively until compatibility is verified.

Wire-layout facts were researched from the public GPL-3.0
[Casement KDrive client](https://github.com/Inkbraid/casement-plugin-x2go)
and its documented behavior; this is an independent implementation, with no
third-party source or captured test data copied into the project. Tests use
synthetic packets. Actual server compatibility, version assumptions, partial
I/O, and teardown still need live X2Go verification.

`ui/src/platform/kdrive-image-decoder.ts` decodes JPEG/PNG regions using the
WebView's `createImageBitmap` and canvas APIs. It checks encoded size and
header dimensions before invoking the decoder and checks decoded dimensions
again, serializes calls, and frees temporary image/canvas resources. It is not
wired to the Rust wire parser or frame cache. WebView support, malicious image
handling and color behavior must be tested on Linux, Windows and macOS. Native
image-library behavior cannot be proven safe solely by header checks.

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
how to recover after a limit or cache miss remain to be determined. The module
is not connected to a wire parser or viewer.

## Input capture

`DesktopInput` captures keyboard, mouse buttons, motion and wheel events on the
focused canvas, and releases held keys and buttons on focus loss or teardown.
It starts disabled; a future session must enable it only when ready and deliver
its callback events to the backend in order. It exposes browser physical and
logical key identifiers, not X keysyms or KDrive packets. Composition/IME and
clipboard handling are not implemented. On transport failure the backend must
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
- A usable viewer still needs to connect the parser, image decoder and cache;
  translate KDrive cache operations and input; synchronize, manage lifecycle,
  and run integration tests. Clipboard, cursor and UDP support are not present.
- A [public KDrive client release announcement](https://www.mail-archive.com/x2go-announcements@lists.x2go.org/msg00217.html)
  mentions version negotiation before requesting the main image and geometry
  updates to elicit an initial image. It does not provide a complete message
  layout. The independent wire framing implementation described above uses
  protocol-layout facts from the other public client reference.

An X2Go session also has to be started or resumed on the server before graphics
can flow. The [x2gostartagent manual](https://github.com/eugenesan/x2goserver/blob/master/x2goserver/man/man8/x2gostartagent.8)
describes required session parameters and returned graphics connection details.
Starting an agent without a functioning decoder and reliable teardown would
leave a remote session running without a usable viewer, so the current code
does not invoke it. The independent `x2go_control` module constructs a
restricted startup command and validates the documented startup reply without
executing either startup or termination. It treats the session cookie as a
secret and does not include it in debug output or parse errors. These primitives
are not yet connected to the SSH session or a graphics backend. The parser's
accepted response forms still need verification against live X2Go servers.

`x2go_transport::open_graphics_stream` can open the validated agent's graphics
port on the destination's loopback through an already-authenticated SSH
connection. The caller must use the same destination connection that created
the agent; it never falls back to direct TCP. The handshake and wire decoder
can process that stream as described above, but are not connected to a viewer.
Opening or dropping the stream does not start or terminate an agent. The SSH
mock integration tests are included but have not been run in this environment;
they use an echo server, not X2Go.

## Still required for a working viewer

- Integrate and verify KDrive wire decoding, image decoding, framebuffer cache
  and rendering on Linux, Windows and macOS without a separately installed
  viewer. The GPL clients cannot simply be copied into this PolyForm-licensed
  project.
- Authenticate and start/resume the X2Go session using the selected server,
  enforcing the existing host-key, proxy and jump-host policies. Never fall
  back silently to a different connection path or leak credentials.
- Convert decoded display updates into the bounded frame contract, handle
  reconnects and full-frame resynchronization, and apply backpressure without
  corrupting delta order.
- Create a separate resizable LinSCP window and connect keyboard, pointer,
  resize, clipboard and session lifecycle events to the actual KDrive backend.
- Test real remote sessions, input, resizing, reconnect and teardown on each
  supported desktop OS. Unit tests with decoded pixels alone cannot validate
  KDrive compatibility or prove that a remote window opens.
