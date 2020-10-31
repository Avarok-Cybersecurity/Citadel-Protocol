#![feature(proc_macro_span)]
//! Contains macros for the hyxe library

/*
#![deny(
missing_docs,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
)]
*/

extern crate proc_macro;
extern crate quote;
extern crate syn;

use syn::export::TokenStream;

enum ThreadedMode {
    Single,
    Multi
}

const BUILD_TYPE: ThreadedMode = ThreadedMode::Single;

#[proc_macro]
pub fn define_struct(item: TokenStream) -> TokenStream {
    let item = item.to_string();
    let args = item.split(",").collect::<Vec<&str>>();
    assert_eq!(args.len(), 2);
    let struct_name = args[0].trim();
    let inner_device = args[1].trim();
    match BUILD_TYPE {
        ThreadedMode::Single => {
            format!("pub struct {} {{ pub inner: Rc<RefCell<{}>> }}", struct_name, inner_device).parse().unwrap()
        }

        ThreadedMode::Multi => {
            format!("pub struct {} {{ pub inner: Arc<RwLock<{}>> }}", struct_name, inner_device).parse().unwrap()
        }
    }
}

#[proc_macro]
pub fn borrown(item: TokenStream) -> TokenStream {
    let item = item.to_string();
    let args = item.split(",").collect::<Vec<&str>>();
    assert_eq!(args.len(), 1);
    let var = args[0].trim();
    match BUILD_TYPE {
        ThreadedMode::Single => {
            format!("{}.inner.borrow()", var).parse().unwrap()
        }

        ThreadedMode::Multi => {
            format!("{}.inner.read()", var).parse().unwrap()
        }
    }
}

#[proc_macro]
pub fn borrow_mut(item: TokenStream) -> TokenStream {
    let item = item.to_string();
    let args = item.split(",").collect::<Vec<&str>>();
    assert_eq!(args.len(), 1);
    let var = args[0].trim();
    match BUILD_TYPE {
        ThreadedMode::Single => {
            format!("{}.borrow_mut()", var).parse().unwrap()
        }

        ThreadedMode::Multi => {
            format!("{}.write()", var).parse().unwrap()
        }
    }
}