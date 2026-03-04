use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derive macro that generates a `Merge` impl for a struct.
///
/// Every field must itself implement `Merge`. This is satisfied out of the box
/// by `Option<T>` (CLI wins if `Some`) and by any struct that also derives
/// `Merge` (e.g. `CommonOptions` nested inside `LocalModeOptions`).
#[proc_macro_derive(Merge)]
pub fn derive_merge(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => panic!("Merge can only be derived for structs with named fields"),
        },
        _ => panic!("Merge can only be derived for structs"),
    };

    let merge_fields = fields.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        quote! {
            self.#ident.merge(#ident);
        }
    });

    let destructure_fields = fields.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        quote! { #ident }
    });

    let expanded = quote! {
        impl Merge for #name {
            fn merge(&mut self, other: Self) {
                let Self { #(#destructure_fields),* } = other;
                #(#merge_fields)*
            }
        }
    };

    TokenStream::from(expanded)
}
