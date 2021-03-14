/// bindings for `libscrap`

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart' as ffi;

// ignore_for_file: unused_import, camel_case_types, non_constant_identifier_names
final DynamicLibrary _dl = _open();
/// Reference to the Dynamic Library, it should be only used for low-level access
final DynamicLibrary dl = _dl;
DynamicLibrary _open() {
  if (Platform.isAndroid) return DynamicLibrary.open('libscrap_ffi.so');
  if (Platform.isIOS) return DynamicLibrary.executable();
  throw UnsupportedError('This platform is not supported.');
}

/// <p class="para-brief"> Meant to be executed by background isolates needing access to the account manager (e.g., FCM)</p>
Pointer<ffi.Utf8> background_processor(
  Pointer<ffi.Utf8> packet,
  Pointer<ffi.Utf8> home_dir,
) {
  return _background_processor(packet, home_dir);
}
final _background_processor_Dart _background_processor = _dl.lookupFunction<_background_processor_C, _background_processor_Dart>('background_processor');
typedef _background_processor_C = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> packet,
  Pointer<ffi.Utf8> home_dir,
);
typedef _background_processor_Dart = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> packet,
  Pointer<ffi.Utf8> home_dir,
);

/// C function `error_message_utf8`.
int error_message_utf8(
  Pointer<ffi.Utf8> buf,
  int length,
) {
  return _error_message_utf8(buf, length);
}
final _error_message_utf8_Dart _error_message_utf8 = _dl.lookupFunction<_error_message_utf8_C, _error_message_utf8_Dart>('error_message_utf8');
typedef _error_message_utf8_C = Int32 Function(
  Pointer<ffi.Utf8> buf,
  Int32 length,
);
typedef _error_message_utf8_Dart = int Function(
  Pointer<ffi.Utf8> buf,
  int length,
);

/// C function `is_kernel_loaded`.
int is_kernel_loaded() {
  return _is_kernel_loaded();
}
final _is_kernel_loaded_Dart _is_kernel_loaded = _dl.lookupFunction<_is_kernel_loaded_C, _is_kernel_loaded_Dart>('is_kernel_loaded');
typedef _is_kernel_loaded_C = Int32 Function();
typedef _is_kernel_loaded_Dart = int Function();

/// C function `last_error_length`.
int last_error_length() {
  return _last_error_length();
}
final _last_error_length_Dart _last_error_length = _dl.lookupFunction<_last_error_length_C, _last_error_length_Dart>('last_error_length');
typedef _last_error_length_C = Int32 Function();
typedef _last_error_length_Dart = int Function();

/// C function `load_page`.
int load_page(
  int port,
  Pointer<ffi.Utf8> home_dir,
) {
  return _load_page(port, home_dir);
}
final _load_page_Dart _load_page = _dl.lookupFunction<_load_page_C, _load_page_Dart>('load_page');
typedef _load_page_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> home_dir,
);
typedef _load_page_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> home_dir,
);

/// C function `memfree`.
int memfree(
  Pointer<ffi.Utf8> ptr,
) {
  return _memfree(ptr);
}
final _memfree_Dart _memfree = _dl.lookupFunction<_memfree_C, _memfree_Dart>('memfree');
typedef _memfree_C = Int32 Function(
  Pointer<ffi.Utf8> ptr,
);
typedef _memfree_Dart = int Function(
  Pointer<ffi.Utf8> ptr,
);

/// C function `send_to_kernel`.
Pointer<ffi.Utf8> send_to_kernel(
  Pointer<ffi.Utf8> packet,
) {
  return _send_to_kernel(packet);
}
final _send_to_kernel_Dart _send_to_kernel = _dl.lookupFunction<_send_to_kernel_C, _send_to_kernel_Dart>('send_to_kernel');
typedef _send_to_kernel_C = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> packet,
);
typedef _send_to_kernel_Dart = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> packet,
);

/// Binding to `allo-isolate` crate
void store_dart_post_cobject(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
) {
  _store_dart_post_cobject(ptr);
}
final _store_dart_post_cobject_Dart _store_dart_post_cobject = _dl.lookupFunction<_store_dart_post_cobject_C, _store_dart_post_cobject_Dart>('store_dart_post_cobject');
typedef _store_dart_post_cobject_C = Void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
typedef _store_dart_post_cobject_Dart = void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
