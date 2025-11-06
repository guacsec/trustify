use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, parse_macro_input};

#[proc_macro_derive(Query)]
pub fn query_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a abstract syntax tree
    // that we can manipulate.
    let ast = parse_macro_input!(input as DeriveInput);
    // Build the trait QueryDoc implementation.
    impl_query(&ast)
}

fn impl_query(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let fields = match &ast.data {
        Data::Struct(data_struct) => data_struct
            .fields
            .clone()
            .into_iter()
            .map(|field| match field.ident {
                Some(ref ident) => ident.to_string(),
                None => String::default(),
            })
            .collect::<Vec<String>>(),
        Data::Enum(_) => vec![],
        Data::Union(_) => vec![],
    };
    let field_names = format!("\"{}\"", fields.join("\" | \""));
    let query_description = format!(
        r#"Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):
```text
(* Query Grammar - EBNF Compliant *)
query = ( values | filter ) , {{ "&" , query }} ;
values = value , {{ "|" , value }} ;
filter = field , operator , values ;
operator = "=" | "!=" | "~" | "!~" | ">=" | ">" | "<=" | "<" ;
field = ({field_names})
value = {{ value_char }} ;
value_char = escaped_char | normal_char ;
escaped_char = "\" , special_char ;
normal_char = ? any character except '&', '|', '=', '!', '~', '>', '<', '\' ? ;
special_char = "&" | "|" | "=" | "!" | "~" | ">" | "<" | "\" ;
```
Examples:
- Simple filter: title=example
- Multiple values filter: title=foo|bar|baz
- Complex filter: modified>2024-01-01
- Combined query: title=foo&average_severity=high
- Escaped characters: title=foo\\&bar
"#
    );
    let sort_description = format!(
        "EBNF grammar for the _sort_ parameter:
```text
    sort = field [ ':', order ] {{ ',' sort }}
    order = ( \"asc\" | \"desc\" )
    field = ({field_names})
```
The optional _order_ should be one of \"asc\" or \"desc\". If
omitted, the order defaults to \"asc\".

Each _field_ name must correspond to one of the columns of the
table holding the entities being queried. Those corresponding
to JSON objects in the database may use a ':' to delimit the
column name and the object key,
e.g. `purl:qualifiers:type:desc`"
    );

    let generated = quote! {
        impl trustify_query::Query for #name {
            fn generate_query_description() -> String {
                #query_description.to_string()
            }

            fn generate_sort_description() -> String {
                #sort_description.to_string()
            }
        }
    };
    generated.into()
}
