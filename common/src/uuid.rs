pub mod serde {

    pub mod urn {

        use serde::{Deserialize, Deserializer, Serializer, de::Error};
        use uuid::Uuid;
        use uuid::serde::urn::serialize as uuid_urn_serialize;

        pub fn serialize<S>(value: &Option<Uuid>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(uuid) => uuid_urn_serialize(uuid, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<String>::deserialize(deserializer)?
                .map(|s| Uuid::parse_str(&s).map_err(D::Error::custom))
                .transpose()
        }
    }
}
