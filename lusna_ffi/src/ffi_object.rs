use jni::{JNIEnv, Executor};
use jni::objects::{JClass, GlobalRef, JObject};
use std::sync::Arc;

/// Meant to be stored inside
pub struct FFIObject {
    pub executor: Executor,
    pub clazz: GlobalRef
}

unsafe impl Send for FFIObject {}
unsafe impl Sync for FFIObject {}

impl FFIObject {
    pub fn new(env: &JNIEnv<'static>, clazz: &JClass<'static>) -> Self {
        // ensure the object lasts statically. This ensures the class doesn't get cleaned up by the VM
        let clazz = env.new_global_ref(clazz.clone()).unwrap();
        let vm = env.get_java_vm().unwrap();
        let executor = Executor::new(Arc::new(vm));
        Self { executor, clazz }
    }

    pub fn execute(&self, fx: impl FnOnce(&JNIEnv, JObject)) {
        let clazz = self.clazz.as_obj();
        self.executor.with_attached(|env| {
            Ok((fx)(env, clazz))
        }).unwrap()
    }
}