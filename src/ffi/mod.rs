///! JNI entry points for the Android app under android/.
///
/// The app owns the transport: it holds an `IsoDep` connection to the tag and
/// hands each APDU to the chip itself. So there is one call here, and it takes
/// a `Transceiver` to talk through. Everything it learns comes back as JSON,
/// which keeps the boundary one string wide rather than a Kotlin class per
/// data group.
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jintArray, jstring};
use jni::JNIEnv;
use log::LevelFilter;
use serde::Deserialize;

use crate::session::{self, AccessKey, ReadOptions};
use crate::smartcard_abstractions::CallbackSmartcard;

mod logger;
mod report;

use report::Report;

/// What the app asks for, as JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    access_key: JsonAccessKey,
    #[serde(default)]
    read_binary_files: bool,
    /// Where to write the document's files. The app passes a directory inside
    /// its own storage, which it has already created.
    #[serde(default)]
    dump_path: Option<String>,
    #[serde(default)]
    file_prefix: Option<String>,
    /// One of trace/debug/info/warn/error. Anything else means info.
    #[serde(default)]
    log_level: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum JsonAccessKey {
    #[serde(rename_all = "camelCase")]
    Mrz {
        document_number: String,
        date_of_birth: String,
        date_of_expiry: String,
    },
    #[serde(rename_all = "camelCase")]
    Can { value: String },
}

impl From<JsonAccessKey> for AccessKey {
    fn from(access_key: JsonAccessKey) -> AccessKey {
        return match access_key {
            JsonAccessKey::Mrz {
                document_number,
                date_of_birth,
                date_of_expiry,
            } => AccessKey::Mrz {
                document_number,
                date_of_birth,
                date_of_expiry,
            },
            JsonAccessKey::Can { value } => AccessKey::Can(value),
        };
    }
}

fn log_level(name: &Option<String>) -> LevelFilter {
    return match name.as_deref().unwrap_or("info").to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };
}

/// Read a document over a tag the app has already connected to.
///
/// `transceiver` implements `PassaufNative.Transceiver`, `progress` implements
/// `PassaufNative.ProgressListener` or is null. Returns the report as JSON;
/// a null return means the JVM is in no state to be given a string.
#[no_mangle]
pub extern "system" fn Java_zone_ave_passauf_PassaufNative_nativeReadDocument<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    options_json: JString<'local>,
    transceiver: JObject<'local>,
    progress: JObject<'local>,
) -> jstring {
    logger::install();

    let options_json: String = match env.get_string(&options_json) {
        Ok(text) => text.into(),
        Err(error) => {
            return to_java_string(
                &mut env,
                &Report::failure(format!("Could not read the options: {}", error)),
            )
        }
    };

    let options: Options = match serde_json::from_str(&options_json) {
        Ok(options) => options,
        Err(error) => {
            return to_java_string(
                &mut env,
                &Report::failure(format!("Could not understand the options: {}", error)),
            )
        }
    };

    logger::begin_capture(log_level(&options.log_level));

    // The closures below need the environment to call back into Kotlin, and
    // they are handed out to two different places, so it lives in a cell they
    // can share. Only one of them is ever running at a time.
    let env_cell = RefCell::new(env);

    // A panic below this point would otherwise unwind straight through the JNI
    // boundary, which is undefined behaviour. Plenty of the layers underneath
    // assert rather than return, and a card leaving the field mid-read is
    // exactly the sort of thing that trips them.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        read(&env_cell, &transceiver, &progress, options)
    }));

    let mut env = env_cell.into_inner();
    let log = logger::take_capture();

    let report = match outcome {
        Ok(Ok(read)) => report::build(&read, log),
        Ok(Err(error)) => Report {
            log,
            ..Report::failure(error)
        },
        Err(payload) => Report {
            log,
            ..Report::failure(format!(
                "passauf crashed while reading: {}",
                panic_message(&payload)
            ))
        },
    };

    return to_java_string(&mut env, &report);
}

/// Decode a JPEG 2000 image so the app can draw it.
///
/// Android's BitmapFactory has no JPEG 2000 decoder, and a good many issuers
/// encode DG2 that way. This has nothing to do with reading or checking a
/// document: it is the app asking for help with a picture it already has.
///
/// Returns an int array of `[width, height, pixels...]`, one packed ARGB_8888
/// pixel each, or null if the data does not decode. The header is an internal
/// arrangement between this function and `PassaufNative.decodeJpeg2000`.
#[no_mangle]
pub extern "system" fn Java_zone_ave_passauf_PassaufNative_nativeDecodeJpeg2000<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    data: JByteArray<'local>,
) -> jintArray {
    logger::install();

    let bytes = match env.convert_byte_array(&data) {
        Ok(bytes) => bytes,
        Err(error) => {
            log::error!("Could not read the image to decode: {}", error);
            return JObject::null().into_raw();
        }
    };

    let image = match crate::images::decode_jpeg2000(&bytes) {
        Some(image) => image,
        None => return JObject::null().into_raw(),
    };

    // Android wants one packed ARGB int per pixel, which is a different byte
    // order from the RGBA the decoder produces.
    let mut packed: Vec<i32> = Vec::with_capacity(2 + image.data.len() / 4);
    packed.push(image.width as i32);
    packed.push(image.height as i32);
    for pixel in image.data.chunks_exact(4) {
        let argb = (u32::from(pixel[3]) << 24)
            | (u32::from(pixel[0]) << 16)
            | (u32::from(pixel[1]) << 8)
            | u32::from(pixel[2]);
        packed.push(argb as i32);
    }

    let array = match env.new_int_array(packed.len() as i32) {
        Ok(array) => array,
        Err(error) => {
            log::error!("Could not allocate room for the decoded image: {}", error);
            return JObject::null().into_raw();
        }
    };
    if let Err(error) = env.set_int_array_region(&array, 0, &packed) {
        log::error!("Could not return the decoded image: {}", error);
        return JObject::null().into_raw();
    }
    return array.into_raw();
}

/// Everything that happens between the two JNI conversions.
fn read<'local>(
    env_cell: &RefCell<JNIEnv<'local>>,
    transceiver: &JObject<'local>,
    progress: &JObject<'local>,
    options: Options,
) -> Result<session::DocumentRead, String> {
    let access_key: AccessKey = options.access_key.into();
    let read_options = ReadOptions {
        file_prefix: options
            .file_prefix
            .unwrap_or_else(|| session::file_prefix_for(&access_key)),
        access_key,
        read_binary_files: options.read_binary_files,
        dump_path: options.dump_path.map(PathBuf::from),
        // Nothing here has a terminal to print to.
        print: false,
    };

    let mut smartcard: Box<dyn crate::smartcard_abstractions::Smartcard> =
        Box::new(CallbackSmartcard::new(|apdu: &[u8]| {
            return transceive(env_cell, transceiver, apdu);
        }));

    let mut report_progress = |stage: session::Progress| {
        notify_progress(env_cell, progress, &stage);
    };

    return session::read_document(&mut smartcard, &read_options, &mut report_progress)
        .map_err(|error| error.to_string());
}

/// Hand one APDU to `IsoDep.transceive` and bring the response back.
fn transceive<'local>(
    env_cell: &RefCell<JNIEnv<'local>>,
    transceiver: &JObject<'local>,
    apdu: &[u8],
) -> Option<Vec<u8>> {
    let mut env = env_cell.borrow_mut();

    let command = match env.byte_array_from_slice(apdu) {
        Ok(command) => command,
        Err(error) => {
            log::error!("Could not hand the APDU to the tag: {}", error);
            return None;
        }
    };

    let response = env.call_method(
        transceiver,
        "transceive",
        "([B)[B",
        &[JValue::Object(&command)],
    );

    // A tag leaving the field throws, and the exception has to be cleared
    // before anything else touches this environment.
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        log::warn!("The tag threw while exchanging an APDU, most likely it moved out of range.");
        return None;
    }

    let response = match response.and_then(|value| value.l()) {
        Ok(response) => response,
        Err(error) => {
            log::error!("The tag returned nothing usable: {}", error);
            return None;
        }
    };
    if response.is_null() {
        return None;
    }

    let response = JByteArray::from(response);
    return match env.convert_byte_array(&response) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            log::error!("Could not read the tag's response: {}", error);
            None
        }
    };
}

/// Tell the app where the read has got to, if it asked to be told.
fn notify_progress<'local>(
    env_cell: &RefCell<JNIEnv<'local>>,
    progress: &JObject<'local>,
    stage: &session::Progress,
) {
    if progress.is_null() {
        return;
    }
    let mut env = env_cell.borrow_mut();

    // The stage name is for the app to branch on, the message for it to show.
    let name = match stage {
        session::Progress::ReadingCardAccess => "readingCardAccess",
        session::Progress::Authenticating => "authenticating",
        session::Progress::Authenticated(_) => "authenticated",
        session::Progress::ReadingFile(_) => "readingFile",
        session::Progress::Checking => "checking",
        session::Progress::Done => "done",
    };

    let (name, message) = match (env.new_string(name), env.new_string(stage.to_string())) {
        (Ok(name), Ok(message)) => (name, message),
        _ => return,
    };

    let called = env.call_method(
        progress,
        "onProgress",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[JValue::Object(&name), JValue::Object(&message)],
    );
    // Progress is decoration; an app that throws from it should not take the
    // read down with it.
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    let _ = called;
}

/// Serialize the report and hand it to the JVM.
fn to_java_string(env: &mut JNIEnv, report: &Report) -> jstring {
    let json = serde_json::to_string(report).unwrap_or_else(|error| {
        // Falling back by hand, since the thing that failed is the serializer.
        format!(
            "{{\"ok\":false,\"error\":\"Could not serialize the report: {}\",\
             \"files\":[],\"portraits\":[],\"warnings\":[],\"log\":[]}}",
            error.to_string().replace('"', "'")
        )
    });

    return match env.new_string(json) {
        Ok(text) => text.into_raw(),
        Err(error) => {
            log::error!("Could not return the report: {}", error);
            JObject::null().into_raw()
        }
    };
}

/// The message a panic carried, for the report.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return message.to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    return "no message".to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app sends the access key as a tagged object, and getting either
    /// variant wrong means a read that cannot possibly succeed.
    #[test]
    fn reads_both_kinds_of_access_key() {
        let options: Options = serde_json::from_str(
            r#"{"accessKey":{"type":"mrz","documentNumber":"A123B234",
                "dateOfBirth":"030201","dateOfExpiry":"350212"},
                "readBinaryFiles":true,"dumpPath":"/tmp/x"}"#,
        )
        .unwrap();
        assert!(options.read_binary_files);
        assert_eq!(options.dump_path, Some("/tmp/x".to_string()));
        match AccessKey::from(options.access_key) {
            AccessKey::Mrz {
                document_number,
                date_of_birth,
                date_of_expiry,
            } => {
                assert_eq!(document_number, "A123B234");
                assert_eq!(date_of_birth, "030201");
                assert_eq!(date_of_expiry, "350212");
            }
            _ => panic!("expected an MRZ access key"),
        }

        let options: Options =
            serde_json::from_str(r#"{"accessKey":{"type":"can","value":"123456"}}"#).unwrap();
        // Anything the app leaves out has to take a safe default.
        assert!(!options.read_binary_files);
        assert_eq!(options.dump_path, None);
        match AccessKey::from(options.access_key) {
            AccessKey::Can(value) => assert_eq!(value, "123456"),
            _ => panic!("expected a CAN access key"),
        }
    }

    #[test]
    fn falls_back_to_info_for_an_unknown_log_level() {
        assert_eq!(log_level(&Some("debug".to_string())), LevelFilter::Debug);
        assert_eq!(log_level(&None), LevelFilter::Info);
        assert_eq!(log_level(&Some("shout".to_string())), LevelFilter::Info);
    }
}
