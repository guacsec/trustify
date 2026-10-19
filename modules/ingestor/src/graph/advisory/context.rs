//! The product context of advisory assertions.
//!
//! An assertion is often stated about a component *in a product*, e.g. CSAF "golang as a default
//! component of Red Hat Storage 3". The context is that product, distilled to what the document
//! states about it: its identifiers, its name, and how the subject relates to it. Nothing is
//! derived (no CPE widening, no versions), that's up to the correlation engine.

use crate::graph::cpe::CpeCreator;
use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use std::collections::{BTreeMap, BTreeSet};
use trustify_common::{cpe::Cpe, db::chunk::EntityChunkedIter};
use trustify_entity::{
    assertion_context::{self, AssertionContextCategory},
    assertion_context_identifier::{self, ContextIdentifierKind},
};
use uuid::Uuid;

/// Namespace of the IDs of assertion contexts.
const NAMESPACE: Uuid = Uuid::from_bytes([
    0x2b, 0x8e, 0x41, 0x7c, 0x0d, 0x5a, 0x4f, 0x93, 0xa6, 0x1e, 0x73, 0xc4, 0x58, 0x09, 0xbd, 0x26,
]);

/// An identifier of a context.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContextIdentifier {
    pub kind: ContextIdentifierKind,
    /// The canonical value: a CPE (URI form), a PURL, `algorithm:digest`, or a plain value.
    pub value: String,
}

/// The product an assertion is stated in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AssertionContext {
    pub category: Option<AssertionContextCategory>,
    pub name: String,
    pub identifiers: BTreeSet<ContextIdentifier>,
    /// The CPEs among the identifiers, to be created.
    pub cpes: BTreeMap<String, Cpe>,
}

impl AssertionContext {
    /// Add a CPE.
    pub fn add_cpe(&mut self, cpe: Cpe) {
        let value = cpe.to_string();
        self.identifiers.insert(ContextIdentifier {
            kind: ContextIdentifierKind::Cpe,
            value: value.clone(),
        });
        self.cpes.insert(value, cpe);
    }

    /// Add an identifier which isn't a CPE.
    pub fn add(&mut self, kind: ContextIdentifierKind, value: impl Into<String>) {
        self.identifiers.insert(ContextIdentifier {
            kind,
            value: value.into(),
        });
    }

    /// The deterministic ID: from the category and the identifiers, or the name, without any.
    pub fn uuid(&self) -> Uuid {
        let category = self
            .category
            .map(|category| format!("{category:?}"))
            .unwrap_or_default();
        let mut id = Uuid::new_v5(&NAMESPACE, category.as_bytes());
        if self.identifiers.is_empty() {
            return Uuid::new_v5(&id, self.name.as_bytes());
        }
        for identifier in &self.identifiers {
            id = Uuid::new_v5(&id, format!("{:?}", identifier.kind).as_bytes());
            id = Uuid::new_v5(&id, identifier.value.as_bytes());
        }
        id
    }
}

/// Creates assertion contexts in batch.
#[derive(Debug, Default)]
pub struct ContextCreator {
    contexts: BTreeMap<Uuid, AssertionContext>,
}

impl ContextCreator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a context, returning its ID.
    pub fn add(&mut self, context: AssertionContext) -> Uuid {
        let id = context.uuid();
        self.contexts.entry(id).or_insert(context);
        id
    }

    /// Create the contexts and their identifiers (including the CPEs), skipping existing ones.
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        if self.contexts.is_empty() {
            return Ok(());
        }

        let mut cpes = CpeCreator::new();
        let mut contexts = Vec::with_capacity(self.contexts.len());
        let mut identifiers = Vec::new();

        // the map is ordered by ID, keeping the lock order stable
        for (id, context) in self.contexts {
            for identifier in &context.identifiers {
                let cpe = context
                    .cpes
                    .get(&identifier.value)
                    .filter(|_| identifier.kind == ContextIdentifierKind::Cpe);
                identifiers.push(assertion_context_identifier::ActiveModel {
                    context_id: Set(id),
                    kind: Set(identifier.kind),
                    value: Set(identifier.value.clone()),
                    cpe_id: Set(cpe.map(Cpe::uuid)),
                });
            }
            for cpe in context.cpes.into_values() {
                cpes.add(cpe);
            }
            contexts.push(assertion_context::ActiveModel {
                id: Set(id),
                category: Set(context.category),
                name: Set(context.name),
            });
        }

        cpes.create(db).await?;

        for batch in contexts.chunked() {
            assertion_context::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(db)
                .await?;
        }
        for batch in identifiers.chunked() {
            assertion_context_identifier::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    fn context(cpe: &str) -> AssertionContext {
        let mut context = AssertionContext {
            category: Some(AssertionContextCategory::DefaultComponentOf),
            name: "Red Hat Storage 3".into(),
            ..Default::default()
        };
        context.add_cpe(Cpe::from_str(cpe).expect("valid CPE"));
        context
    }

    /// The ID depends on category and identifiers, not on the name (which varies between
    /// documents for the same product).
    #[test]
    fn stable_id() {
        let a = context("cpe:/a:redhat:storage:3");
        let mut b = context("cpe:/a:redhat:storage:3");
        b.name = "Storage 3".into();
        assert_eq!(a.uuid(), b.uuid());

        assert_ne!(a.uuid(), context("cpe:/a:redhat:storage:4").uuid());

        let mut c = a.clone();
        c.category = Some(AssertionContextCategory::InstalledOn);
        assert_ne!(a.uuid(), c.uuid());
    }

    /// Without identifiers, the name identifies the context.
    #[test]
    fn name_without_identifiers() {
        let named = |name: &str| AssertionContext {
            name: name.into(),
            ..Default::default()
        };
        assert_eq!(named("A").uuid(), named("A").uuid());
        assert_ne!(named("A").uuid(), named("B").uuid());
    }
}
