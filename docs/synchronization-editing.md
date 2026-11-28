# Synchronization and editing evidence

Synchronization rejects unsafe names returned by remote listings and granted-folder providers before building paths. The keep-up-to-date watcher retains events received while its initial synchronization is running, instead of discarding them before the next wait. A deterministic host test injects a change during that first pass and requires another pass before the long polling interval.

Remote editor, external-editor staging and content search downloads enforce their byte limits while streaming, even if server metadata understates a file's size. Search rejects unsafe remote listing names. The browser can retry an undecodable file using an explicitly selected encoding without replacing the currently open editor; backend encoding names are matched case-insensitively. Invalid sequences and unrepresentable output remain errors, and binary detection is heuristic.

Linux and Windows mock-session regressions for the watcher, bounded reads, listing validation and partial remote-delete reporting passed in [CI run 46115208371](https://github.com/unsubstantiation/LinSCP/actions/runs/46115208371). The browser retry and lowercase-encoding tests pass in the jsdom UI suite on Linux. Follow-up CI at [run 46115520925](https://github.com/unsubstantiation/LinSCP/actions/runs/46115520925) covers the subsequent validation-order adjustment.

These are not live network interruption, real-world server compatibility, or packaged Android tests. Recursive remote deletion is not transactional: a connection failure may leave a partially deleted tree. Watcher behavior on other providers, physical devices, and non-UTF-8 round trips against live servers remain unverified.
