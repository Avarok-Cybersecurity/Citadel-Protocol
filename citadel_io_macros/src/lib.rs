//! Procedural macros for `citadel_io`.
//!
//! Currently provides [`ErrorRegistry`], a derive that turns a `#[repr(u16)]` fieldless enum into the
//! canonical error-code registry: each variant declares its human-readable message **once** via a
//! `#[form = "..."]` attribute, and the derive generates the lookup/metadata methods used by the
//! `citadel_io::error!` macro and `NetworkError`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, Data, DeriveInput, Expr, ExprLit, Fields, Lit, LitStr};

/// Derive the error-code registry methods on a `#[repr(u16)]` fieldless enum.
///
/// Every variant must carry a `#[form = "template with {} placeholders"]` attribute. Generates an
/// inherent `impl` with:
/// - `raw_string(self) -> &'static str` — the variant's form template.
/// - `as_u16(self) -> u16` — the `#[repr(u16)]` discriminant (the stable error code).
/// - `placeholder_count(self) -> usize` — the number of `{}` placeholders in the form.
///
/// Emits a compile error if a variant is non-unit, lacks `#[form]`, or has unbalanced/`{x}`-style braces.
#[proc_macro_derive(ErrorRegistry, attributes(form))]
pub fn derive_error_registry(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);

    let enum_data = match &input.data {
        Data::Enum(e) => e,
        _ => {
            return syn::Error::new(input.span(), "ErrorRegistry can only be derived for enums")
                .to_compile_error()
                .into()
        }
    };

    let name = &input.ident;
    let mut raw_arms = Vec::new();
    let mut count_arms = Vec::new();

    for variant in &enum_data.variants {
        let vident = &variant.ident;

        if !matches!(variant.fields, Fields::Unit) {
            return syn::Error::new(
                variant.span(),
                "ErrorRegistry variants must be unit variants (no fields)",
            )
            .to_compile_error()
            .into();
        }

        let form = match extract_form(variant) {
            Ok(form) => form,
            Err(err) => return err.to_compile_error().into(),
        };

        let count = match count_placeholders(&form.value()) {
            Ok(count) => count,
            Err(msg) => return syn::Error::new(form.span(), msg).to_compile_error().into(),
        };

        raw_arms.push(quote! { #name::#vident => #form, });
        count_arms.push(quote! { #name::#vident => #count, });
    }

    quote! {
        impl #name {
            /// The variant's canonical format template (declared via `#[form = "..."]`).
            pub const fn raw_string(self) -> &'static str {
                match self { #(#raw_arms)* }
            }

            /// The stable numeric error code (the `#[repr(u16)]` discriminant).
            pub const fn as_u16(self) -> u16 {
                self as u16
            }

            /// The number of `{}` placeholders in the variant's form template.
            pub const fn placeholder_count(self) -> usize {
                match self { #(#count_arms)* }
            }
        }
    }
    .into()
}

/// Pull the `#[form = "..."]` string literal off a variant, or produce a helpful error.
fn extract_form(variant: &syn::Variant) -> syn::Result<LitStr> {
    for attr in &variant.attrs {
        if attr.path().is_ident("form") {
            let nv = attr.meta.require_name_value()?;
            if let Expr::Lit(ExprLit {
                lit: Lit::Str(s), ..
            }) = &nv.value
            {
                return Ok(s.clone());
            }
            return Err(syn::Error::new(
                attr.span(),
                "#[form = \"...\"] must be a string literal",
            ));
        }
    }
    Err(syn::Error::new(
        variant.span(),
        "every ErrorRegistry variant requires a #[form = \"...\"] attribute",
    ))
}

/// Count `{}` placeholders in a form template, treating `{{`/`}}` as escapes. Errors on a lone brace
/// or a non-empty `{...}` group (the registry only supports positional `{}`).
fn count_placeholders(s: &str) -> Result<usize, &'static str> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut count = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    i += 2; // escaped "{{"
                } else if i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    count += 1; // placeholder "{}"
                    i += 2;
                } else {
                    return Err("invalid '{' in form: use '{}' for a placeholder or '{{' to escape a literal brace ('{x}'-style placeholders are not supported)");
                }
            }
            b'}' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    i += 2; // escaped "}}"
                } else {
                    return Err("invalid '}' in form: use '}}' to escape a literal brace");
                }
            }
            _ => i += 1,
        }
    }
    Ok(count)
}
