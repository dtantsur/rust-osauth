use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn;

#[proc_macro_derive(
    PaginatedResource,
    attributes(resource_id, collection_name, flat_collection)
)]
pub fn paginated_resource_macro_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let class_name = &input.ident;
    let vis = &input.vis;
    let maybe_collection_name = get_collection_name(&input);
    let (id_name, id_type) = get_id_field(&input.data);

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

fn has_attr(attrs: &Vec<syn::Attribute>, attr: &str) -> bool {
    attrs.iter().find(|x| x.path.is_ident(attr)).is_some()
}

fn get_id_field(data: &syn::Data) -> (&syn::Ident, &syn::Type) {
    if let syn::Data::Struct(ref st) = data {
        if let syn::Fields::Named(ref fs) = st.fields {
            for field in &fs.named {
                if has_attr(&field.attrs, "resource_id") {
                    return (
                        field.ident.as_ref().expect("no ident for resource_id"),
                        &field.ty,
                    );
                }
            }
        } else {
            panic!("only named fields are supported for derive(PaginatedResource)");
        }
    } else {
        panic!("only structs are supported for derive(PaginatedResource)");
    }

    panic!("#[resource_id] missing");
}

fn get_collection_name(input: &syn::DeriveInput) -> Option<String> {
    let mut flat = false;
    let mut maybe_name = None;
    for attr in &input.attrs {
        match attr.parse_meta() {
            Ok(syn::Meta::NameValue(nv)) if nv.path.is_ident("collection_name") => {
                if flat {
                    panic!("collection_name and flat_collection cannot be used together");
                }
                match nv.lit {
                    syn::Lit::Str(s) => maybe_name = Some(s.value()),
                    _ => panic!("collection_name must be a string"),
                }
            }
            Ok(syn::Meta::Path(p)) if p.is_ident("flat_collection") => {
                if maybe_name.is_some() {
                    panic!("collection_name and flat_collection cannot be used together");
                }
                flat = true;
            }
            _ => {}
        }
    }

    if flat {
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
    }
}
