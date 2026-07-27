///! passauf, as a library.
///
/// The pieces are layered roughly the way a read runs:
///
/// - [`smartcard_abstractions`] gets bytes to and from a card. Bring your own
///   transport with [`smartcard_abstractions::CallbackSmartcard`], or use the
///   PC/SC and Proxmark backends when their features are on.
/// - [`iso7816`] builds and exchanges APDUs, [`secure_messaging`] wraps them
///   once a session exists.
/// - [`icao9303`] and [`pace`] establish that session, with BAC and PACE.
/// - [`dg_parsers`] turns the files that come back into the types in [`types`].
/// - [`session`] drives all of the above and hands back a [`session::DocumentRead`].
///
/// [`session::read_document`] is the whole thing in one call, and is what both
/// the CLI and the Android app use.
pub mod dg_parsers;
pub mod helpers;
pub mod icao9303;
pub mod images;
pub mod iso7816;
#[cfg(feature = "pace")]
pub mod pace;
#[cfg(feature = "proxmark")]
pub mod proxmark;
pub mod secure_messaging;
pub mod session;
pub mod smartcard_abstractions;
pub mod types;

/// The JNI surface the Android app calls. Nothing else should need it.
#[cfg(feature = "android")]
mod ffi;
