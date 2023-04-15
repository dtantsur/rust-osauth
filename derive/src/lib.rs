use std::fmt;

use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TS2};
use quote::{quote, ToTokens};

#[proc_macro_derive(
    PaginatedResource,
    attributes(resource_id, collection_name, flat_collection)
)]
pub fn paginated_resource_macro_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let class_name = &input.ident;
    let vis = &input.vis;
    let maybe_collection_name = match get_collection_name(&input) {
        Ok(name) => name,
        Err(err) => return err.into_compile_error().into(),
    };
    let (id_name, id_type) = match get_id_field(&input) {
        Ok(tpl) => tpl,
        Err(err) => return err.into_compile_error().into(),
    };

    if let Some(collection_name) = maybe_collection_name {
        let collection_ident = syn::Ident::new(&collection_name, Span::call_site());
        let collection_class_name = syn::Ident::new(
            &format!("{}DerivedOSResourceCollection", class_name),
            Span::call_site(),
        );

        quote! {
            #[derive(Debug, ::serde::Deserialize)]
            #[allow(missing_docs, unused)]
            #vis struct #collection_class_name {
                #collection_ident: Vec<#class_name>,
            }

            #[allow(missing_docs, unused)]
            impl ::osauth::PaginatedResource for #class_name {
                type Id = #id_type;
                type Root = #collection_class_name;
                fn resource_id(&self) -> Self::Id {
                    self.#id_name.clone()
                }
            }

            #[allow(missing_docs, unused)]
            impl From<#collection_class_name> for Vec<#class_name> {
                fn from(value: #collection_class_name) -> Vec<#class_name> {
                    value.#collection_ident
                }
            }
        }
    } else {
        quote! {
            #[allow(missing_docs, unused)]
            impl ::osauth::PaginatedResource for #class_name {
                type Id = #id_type;
                type Root = Vec<#class_name>;
                fn resource_id(&self) -> Self::Id {
                    self.#id_name.clone()
                }
            }
        }
    }
    .into()
}

fn get_attr<'a>(attrs: &'a [syn::Attribute], attr: &str) -> Option<&'a syn::Attribute> {
    attrs.iter().find(|x| x.path.is_ident(attr))
}

fn get_id_field(input: &syn::DeriveInput) -> syn::Result<(&syn::Ident, &syn::Type)> {
    let mut default_id = None;
    if let syn::Data::Struct(ref st) = input.data {
        if let syn::Fields::Named(ref fs) = st.fields {
            for field in &fs.named {
                if get_attr(&field.attrs, "resource_id").is_some() {
                    return Ok((
                        field.ident.as_ref().expect("no ident for resource_id"),
                        &field.ty,
                    ));
                }

                if let Some(id) = field.ident.as_ref() {
                    if id == "id" {
                        default_id = Some((id, &field.ty));
                    }
                }
            }
        } else {
            return Err(syn::Error::new_spanned(
                input,
                "only named fields are supported for derive(PaginatedResource)",
            ));
        }
    } else {
        return Err(syn::Error::new_spanned(
            input,
            "only structs are supported for derive(PaginatedResource)",
        ));
    }

    if let Some(id) = default_id {
        Ok(id)
    } else {
        Err(syn::Error::new_spanned(input, "#[resource_id] missing"))
    }
}

fn get_collection_name(input: &syn::DeriveInput) -> syn::Result<Option<String>> {
    let mut flat = false;
    let mut maybe_name = None;
    for attr in &input.attrs {
        match attr.parse_meta() {
            Ok(syn::Meta::NameValue(nv)) if nv.path.is_ident("collection_name") => {
                if flat {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "collection_name and flat_collection cannot be used together",
                    ));
                }
                match nv.lit {
                    syn::Lit::Str(s) => maybe_name = Some(s.value()),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            attr,
                            "collection_name must be a string",
                        ))
                    }
                }
            }
            Ok(syn::Meta::Path(p)) if p.is_ident("flat_collection") => {
                if maybe_name.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "collection_name and flat_collection cannot be used together",
                    ));
                }
                flat = true;
            }
            _ => {}
        }
    }

    Ok(if flat {
        None
    } else {
        maybe_name.or_else(|| {
            let ident = input.ident.to_string().to_case(Case::Snake);
            Some(
                if ident.chars().last().expect("empty collection_name") == 's' {
                    format!("{}es", ident)
                } else {
                    format!("{}s", ident)
                },
            )
        })
    })
}

fn fail<S, M>(span: S, message: M) -> TokenStream
where
    S: ToTokens,
    M: fmt::Display,
{
    syn::Error::new_spanned(span, message)
        .into_compile_error()
        .into()
}

#[proc_macro_derive(QueryItem, attributes(query_item))]
pub fn query_item_macro_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let class_name = &input.ident;
    let fragments = match query_item_fragments(
        class_name,
        match input.data {
            syn::Data::Enum(e) => e,
            _ => {
                return fail(input, "derive(QueryItem) only works on enums");
            }
        },
    ) {
        Ok(f) => f,
        Err(e) => return e.into_compile_error().into(),
    };

    quote! {
        impl ::osauth::QueryItem for #class_name {
            fn query_item(&self) -> ::std::result::Result<(&str, ::std::borrow::Cow<str>), ::osauth::Error> {
                Ok(match self {
                    #(#fragments),*
                })
            }
        }
    }.into()
}

fn query_item_fragments(class_name: &syn::Ident, input: syn::DataEnum) -> syn::Result<Vec<TS2>> {
    let mut result = Vec::with_capacity(input.variants.len());
    for var in input.variants {
        let name = if let Some(attr) = get_attr(&var.attrs, "query_item") {
            match attr.parse_meta()? {
                syn::Meta::NameValue(nv) => match nv.lit {
                    syn::Lit::Str(s) => s.value(),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            attr,
                            "query_item value must be a string",
                        ));
                    }
                },
                _ => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "query_item must have a value",
                    ));
                }
            }
        } else {
            var.ident.to_string().to_case(Case::Snake)
        };
        match var.fields {
            syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field = fields.unnamed.into_iter().next().unwrap();
                result.push(query_item_fragment(class_name, var.ident, &name, field));
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    var,
                    "each variant must have exactly one unnamed type",
                ));
            }
        }
    }
    Ok(result)
}

fn query_item_fragment(
    class_name: &syn::Ident,
    ident: syn::Ident,
    name: &str,
    field: syn::Field,
) -> TS2 {
    let ty = field.ty;
    match ty {
        syn::Type::Path(tp) if tp.qself.is_none() && tp.path.is_ident("String") => {
            quote! {
                #class_name::#ident(var) => (#name, ::std::borrow::Cow::Borrowed(var.as_str()))
            }
        }
        syn::Type::Path(tp) if tp.qself.is_none() && tp.path.is_ident("bool") => {
            quote! {
                #class_name::#ident(var) => {
                    let value = if *var { "true" } else { "false" };
                    (#name, ::std::borrow::Cow::Borrowed(value))
                }
            }
        }
        _ => quote! {
            #class_name::#ident(var) => (#name, var.to_string().into())
        },
    }
}
