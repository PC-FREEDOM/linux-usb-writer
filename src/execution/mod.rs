// Raw Write Capability Boundary. This module exists purely to be a shared
// ancestor of `core`, `linux_access`, and `write_job` so that the small set
// of methods capable of producing a real, writable target for a Gate-passed
// FD (`AuthorizedWrite::into_parts()`, `ActiveWrite::writer_target()`/
// `sync_target()`, `OpenedDeviceHandle::writer_target()`/`sync_target()`) can
// be scoped to `pub(in crate::execution)` -- visible throughout this
// subtree, invisible to `main.rs`, `image_source.rs`, `writer.rs`, and every
// other sibling module. It carries no logic of its own and does not change
// any of the three submodules' existing responsibilities (see each file's
// own module-level doc comment for those).
pub(crate) mod core;
pub(crate) mod linux_access;
pub(crate) mod write_job;
