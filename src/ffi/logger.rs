///! Getting passauf's log somewhere useful on Android.
///
/// Two places, in fact: logcat, so a read can be followed with `adb logcat`,
/// and a per-thread buffer that the JNI call hands back with its report. The
/// app being a tool for looking at documents, the trace of what was read is
/// worth showing rather than throwing away.
use std::cell::RefCell;
use std::panic;
use std::sync::Once;

use log::{Level, LevelFilter, Log, Metadata, Record};

const TAG: &str = "passauf";

thread_local! {
    /// Set for the duration of one read, on the thread doing the reading. Other
    /// threads logging at the same time go to logcat only, so a read's trace
    /// stays its own.
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

static INSTALL: Once = Once::new();

/// Install the logger and a panic hook. Safe to call on every read; only the
/// first one does anything, since a process gets one logger.
pub fn install() {
    INSTALL.call_once(|| {
        // An error here means something else already claimed the logger, which
        // is not worth failing a read over.
        let _ = log::set_boxed_logger(Box::new(AndroidLogger));

        // A panic anywhere below the JNI boundary is caught and turned into an
        // error report, but the message itself only exists in the hook, and the
        // default one writes to a stderr that Android discards.
        panic::set_hook(Box::new(|info| {
            write_to_logcat(Level::Error, &format!("panic: {}", info));
        }));
    });
}

/// Start collecting this thread's log lines, discarding anything left over.
pub fn begin_capture(level: LevelFilter) {
    log::set_max_level(level);
    CAPTURE.with(|capture| *capture.borrow_mut() = Some(vec![]));
}

/// Stop collecting and hand back what was collected.
pub fn take_capture() -> Vec<String> {
    return CAPTURE.with(|capture| capture.borrow_mut().take().unwrap_or_default());
}

struct AndroidLogger;

impl Log for AndroidLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        return metadata.level() <= log::max_level();
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // simplelog's macros run their argument through paris before handing it
        // to log, so what arrives here already has terminal escapes in it.
        let message = strip_ansi(&record.args().to_string());
        write_to_logcat(record.level(), &message);
        CAPTURE.with(|capture| {
            if let Some(lines) = capture.borrow_mut().as_mut() {
                lines.push(format!("{:<5} {}", record.level(), message));
            }
        });
    }

    fn flush(&self) {}
}

/// Remove ANSI escape sequences, which are only meaningful in a terminal.
///
/// Everything paris emits is a CSI sequence: an escape, `[`, some parameter
/// bytes, then a final byte in the 0x40..=0x7E range.
fn strip_ansi(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\x1b' {
            result.push(character);
            continue;
        }
        // Not a CSI sequence after all, so there is nothing to skip past.
        if characters.next() != Some('[') {
            continue;
        }
        for parameter in characters.by_ref() {
            if ('\x40'..='\x7e').contains(&parameter) {
                break;
            }
        }
    }
    return result;
}

#[cfg(target_os = "android")]
fn write_to_logcat(level: Level, message: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    // android/log.h android_LogPriority.
    const ANDROID_LOG_ERROR: c_int = 6;
    const ANDROID_LOG_WARN: c_int = 5;
    const ANDROID_LOG_INFO: c_int = 4;
    const ANDROID_LOG_DEBUG: c_int = 3;
    const ANDROID_LOG_VERBOSE: c_int = 2;

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    let priority = match level {
        Level::Error => ANDROID_LOG_ERROR,
        Level::Warn => ANDROID_LOG_WARN,
        Level::Info => ANDROID_LOG_INFO,
        Level::Debug => ANDROID_LOG_DEBUG,
        Level::Trace => ANDROID_LOG_VERBOSE,
    };

    // An interior nul would truncate the line, so replace rather than drop it.
    let tag = CString::new(TAG).unwrap();
    let text = CString::new(message.replace('\0', "\\0")).unwrap_or_default();
    // Safe: both pointers are nul-terminated and live until the call returns.
    unsafe {
        __android_log_write(priority, tag.as_ptr(), text.as_ptr());
    }
}

/// Building the JNI layer off Android is useful for typechecking it, and there
/// is no logcat to write to there.
#[cfg(not(target_os = "android"))]
fn write_to_logcat(level: Level, message: &str) {
    eprintln!("[{}] {:<5} {}", TAG, level, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// paris colours everything it is given, and none of that belongs in a
    /// buffer the app is going to display.
    #[test]
    fn strips_terminal_escapes() {
        assert_eq!(
            strip_ansi("\x1b[32mEF.DG1 matches\x1b[0m its hash"),
            "EF.DG1 matches its hash"
        );
        assert_eq!(strip_ansi("nothing to strip"), "nothing to strip");
        // A truncated sequence must not swallow the rest of the line's text,
        // nor panic.
        assert_eq!(strip_ansi("plain\x1b"), "plain");
        assert_eq!(strip_ansi("plain\x1b[31"), "plain");
    }
}
