use std::borrow::Cow;
use std::fmt;

use osauth_derive::QueryItem;

#[derive(Debug)]
struct CustomDisplay;

impl fmt::Display for CustomDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("my value")
    }
}

#[derive(Debug, QueryItem)]
enum TestFilter {
    Str(String),
    Int(u32),
    Bool(bool),
    CustomType(CustomDisplay),
    #[query_item = "try_to_guess"]
    CustomName(String),
}

#[test]
fn test_string() {
    use osauth::QueryItem;

    let test = TestFilter::Str("test".into());
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "str");
    assert_eq!(qi.1, Cow::Borrowed("test"));
}

#[test]
fn test_int() {
    use osauth::QueryItem;

    let test = TestFilter::Int(42);
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "int");
    assert_eq!(qi.1, Cow::<str>::Owned("42".into()));
}

#[test]
fn test_bool() {
    use osauth::QueryItem;

    let test = TestFilter::Bool(true);
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "bool");
    assert_eq!(qi.1, Cow::Borrowed("true"));

    let test = TestFilter::Bool(false);
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "bool");
    assert_eq!(qi.1, Cow::Borrowed("false"));
}

#[test]
fn test_custom_type() {
    use osauth::QueryItem;

    let test = TestFilter::CustomType(CustomDisplay);
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "custom_type");
    assert_eq!(qi.1, Cow::<str>::Owned("my value".into()));
}

#[test]
fn test_custom_name() {
    use osauth::QueryItem;

    let test = TestFilter::CustomName("test".into());
    let qi = test.query_item().unwrap();
    assert_eq!(qi.0, "try_to_guess");
    assert_eq!(qi.1, Cow::Borrowed("test"));
}
