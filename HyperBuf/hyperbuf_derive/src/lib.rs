#![feature(custom_attribute, proc_macro_span)]
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
#[macro_use]
extern crate quote;
extern crate syn;

use std::str::FromStr;

use quote::quote;
use syn::{DeriveInput, parse_macro_input};
use syn::export::{Span, TokenStream};
use std::ops::Add;

/*
#[proc_macro_attribute]
pub fn runtime(attr: TokenStream, item: TokenStream) -> TokenStream {
    println!("attr: \"{}\"", attr.to_string());
    println!("item: {}", item.to_string());

    let attr = attr.to_string();

    let raw = item.to_string();
    let mut parts = raw.splitn(4, " ").collect::<Vec<&str>>();

    if parts[0] != "fn" || parts.len() != 4 {
        panic!("Invalid runtime function formatting!");
    }


    let insert = "success!(\"HyxeWave::Runtime initiated\");";
    let mut end = parts[3].to_owned();
    end.truncate(end.len() - 1);
    end += ";success!(\"HyxeWave::Runtime finished\"); }";

    let ret = parts[0].to_owned() + " " + parts[1] + " " + parts[2] + " " + insert + " " + end.as_str();

    TokenStream::from_str(ret.as_str()).unwrap()
}
*/

#[proc_macro_attribute]
pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_str = attr.to_string();

    if !attr_str.contains("depth =") {
        panic!("Must specify depth");
    }

    if !attr_str.contains(",") {
        panic!("Must specify type");
    }

    if !attr_str.contains("expression = ") {
        panic!("Must specify expression");
    }

    if !attr_str.contains("{}") {
        panic!("Must specify variable insertion");
    }

    let code = item.to_string();

    if !code.contains("match") {
        panic!("Must contain a match statement with a variable accompanied by empty open and close brackets (hollow inside)");
    }

    let parts = attr_str.split(",").collect::<Vec<&str>>();
    let part0 = parts[0];
    let part1 = parts[1];

    assert!(parts[0].contains("depth"));
    assert!(parts[1].contains("expression"));

    let part0 = part0.replace("depth = ", "").replace(" ", "");
    let part0 = part0.as_str();
    let depth = isize::from_str(part0).unwrap();

    let part1 = part1.replace("expression = ", "").replace(" ", "").replace(" ", "").replace("\"", "");
    let line_expr = part1.as_str();

    let mut ret0 = String::new();
    let mut store = Vec::<&str>::new();
    let re = &mut store;



    for line in code.lines() {
        if line.contains("match") {
            ret0.push_str("match len {\n\n");
            // We inserted the match, now let's add the innards
            let innards = (1..=depth).into_iter().map(move |idx| {
                idx.to_string() + " => {\n" + (1..=idx).into_iter().map(|idx| {
                    let written_idx = idx - 1;
                    let written_str = written_idx.to_string();
                    let written_str = written_str.as_str();
                    if idx == 1 {
                        "\t\t".to_string() + line_expr.replace("+{}", "").replace("{}", written_str).as_str() + ";\n"
                    } else {
                        "\t\t".to_string() + line_expr.replace("{}", written_str).as_str() + ";\n"
                    }
                }).collect::<String>().as_str() + "},\n\n"
            }).collect::<Vec<String>>();

            let innards: String = innards.concat();
            ret0.push_str(innards.as_str());
            //now, push in the `n` case
            let n_case = "n => {\n\t\tfor n in 0..n as usize {\n\t\t\t".to_string() + line_expr.replace("{}", "n").as_str() + ";\n\t\t}\n\t}\n}\n";
            let n_case = n_case.replace("p0+n", "p0+(n as isize)");
            ret0.push_str(n_case.as_str());
            continue;
        } else {
            ret0.push_str(line);
            ret0.push_str("\n");
        }
    }

    //let collect: String = store.concat();
    //panic!("{}", ret0);

    TokenStream::from_str(ret0.as_str()).unwrap()
}

#[proc_macro]
pub fn make_answer(_item: TokenStream) -> TokenStream {
    "fn answer() -> u32 { 42 }".parse().unwrap()
}


#[proc_macro_derive(HyxeAtom)]
pub fn hyxe_atom(input: TokenStream) -> TokenStream {
    // Construct a represntation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_hello_macro(&ast)
}


fn impl_hello_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl HelloMacro for #name {
            fn hello_macro(&self) {
                println!("Hello, Macro! My name is {}", stringify!(#name));
                let m = 2 + 3;
                println!("val : {}", m);
            }
        }
    };
    gen.into()
}