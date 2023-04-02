use serde::Deserialize;

use osauth_derive::PaginatedResource;

#[derive(Debug, Deserialize, PaginatedResource)]
struct SimpleResource {
    #[resource_id]
    pub id: String,
    #[allow(dead_code)]
    pub not_id: String,
}

#[derive(Debug, Deserialize, PaginatedResource)]
#[collection_name = "items"]
struct RenamedResource {
    #[resource_id]
    pub id: String,
}

#[derive(Debug, Deserialize, PaginatedResource)]
#[flat_collection]
struct FlatResource {
    #[resource_id]
    pub id: String,
}

#[test]
fn test_simple_derive() {
    use osauth::PaginatedResource;

    let res = SimpleResource {
        id: "the id".into(),
        not_id: "not id".into(),
    };

    let res_id: String = res.resource_id();
    assert_eq!(&res_id, "the id");

    let json =
        r#"{"simple_resources": [{"id": "1", "not_id": "abcd"}, {"id": "2", "not_id": "dcba"}]}"#;
    let resources: <SimpleResource as PaginatedResource>::Root =
        serde_json::from_str(json).unwrap();
    assert_eq!(resources.simple_resources.len(), 2);
}

#[test]
fn test_renamed_collection() {
    use osauth::PaginatedResource;

    let res = RenamedResource {
        id: "the id".into(),
    };

    let res_id: String = res.resource_id();
    assert_eq!(&res_id, "the id");

    let json = r#"{"items": [{"id": "1"}, {"id": "2"}]}"#;
    let resources: <RenamedResource as PaginatedResource>::Root =
        serde_json::from_str(json).unwrap();
    assert_eq!(resources.items.len(), 2);
}

#[test]
fn test_flat_collection() {
    use osauth::PaginatedResource;

    let res = FlatResource {
        id: "the id".into(),
    };

    let res_id: String = res.resource_id();
    assert_eq!(&res_id, "the id");

    let json = r#"[{"id": "1"}, {"id": "2"}]"#;
    let resources: <FlatResource as PaginatedResource>::Root = serde_json::from_str(json).unwrap();
    assert_eq!(resources.len(), 2);
}
