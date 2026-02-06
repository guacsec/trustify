use crate::{model::IngestResult, service::Error};
use hex::ToHex;
use roxmltree::{Document, Node};
use sea_orm::{ConnectionTrait, EntityTrait, Iterable, Set, TransactionTrait};
use sea_query::OnConflict;
use std::str::from_utf8;
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, hashing::Digests};
use trustify_entity::{labels::Labels, weakness};

pub struct CweCatalogLoader {}

impl Default for CweCatalogLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl CweCatalogLoader {
    pub fn new() -> Self {
        Self {}
    }

    #[instrument(skip(self, buffer, tx), ret)]
    pub async fn load_bytes(
        &self,
        labels: Labels,
        buffer: &[u8],
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let xml = from_utf8(buffer)?;

        let document = Document::parse(xml)?;

        self.load(labels, &document, digests, tx).await
    }

    #[instrument(skip(self, doc, tx), ret)]
    pub async fn load<'x>(
        &self,
        _labels: Labels,
        doc: &Document<'x>,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let root = doc.root();

        let catalog = root.first_element_child();
        if let Some(catalog) = catalog {
            let weaknesses = catalog.first_element_child();
            let mut batch = Vec::new();

            if let Some(weaknesses) = weaknesses {
                for weakness in weaknesses.children() {
                    if weakness.is_element() {
                        let mut child_of = Vec::new();
                        let mut parent_of = Vec::new();
                        let mut starts_with = Vec::new();
                        let mut can_follow = Vec::new();
                        let mut can_precede = Vec::new();
                        let mut required_by = Vec::new();
                        let mut requires = Vec::new();
                        let mut can_also_be = Vec::new();
                        let mut peer_of = Vec::new();

                        if let Some(id) = weakness.attribute("ID").map(|id| format!("CWE-{id}")) {
                            let mut description = None;
                            let mut extended_description = None;

                            if let Some(description_node) =
                                weakness.children().find(|e| e.has_tag_name("Description"))
                            {
                                description = description_node.text().map(|e| e.to_string());
                            }

                            if let Some(extended_description_node) = weakness
                                .children()
                                .find(|e| e.has_tag_name("Extended_Description"))
                            {
                                extended_description
                                    .replace(gather_content(&extended_description_node));
                            }

                            if let Some(related_weaknesses) = weakness
                                .children()
                                .find(|e| e.has_tag_name("Related_Weaknesses"))
                            {
                                for related in related_weaknesses
                                    .children()
                                    .filter(|e| e.has_tag_name("Related_Weakness"))
                                {
                                    if let Some(target) = related.attribute("CWE_ID")
                                        && let Some(nature) = related.attribute("Nature")
                                        && let Some(dest) = match nature {
                                            "ChildOf" => Some(&mut child_of),
                                            "ParentOf" => Some(&mut parent_of),
                                            "StartsWith" => Some(&mut starts_with),
                                            "CanFollow" => Some(&mut can_follow),
                                            "CanPrecede" => Some(&mut can_precede),
                                            "RequiredBy" => Some(&mut required_by),
                                            "Requires" => Some(&mut requires),
                                            "CanAlsoBe" => Some(&mut can_also_be),
                                            "PeerOf" => Some(&mut peer_of),
                                            _ => None,
                                        }
                                    {
                                        dest.push(target.to_string());
                                    }
                                }
                            }

                            batch.push(weakness::ActiveModel {
                                id: Set(id),
                                description: Set(description),
                                extended_description: Set(extended_description),
                                child_of: Set(normalize(child_of)),
                                parent_of: Set(normalize(parent_of)),
                                starts_with: Set(normalize(starts_with)),
                                can_follow: Set(normalize(can_follow)),
                                can_precede: Set(normalize(can_precede)),
                                required_by: Set(normalize(required_by)),
                                requires: Set(normalize(requires)),
                                can_also_be: Set(normalize(can_also_be)),
                                peer_of: Set(normalize(peer_of)),
                            });
                        }
                    }
                }

                for chunk in &batch.chunked() {
                    weakness::Entity::insert_many(chunk)
                        .on_conflict(
                            OnConflict::column(weakness::Column::Id)
                                .update_columns(weakness::Column::iter())
                                .to_owned(),
                        )
                        .exec(tx)
                        .await?;
                }
            }
        }

        Ok(IngestResult {
            // Returning the digest as "id", this is far from optional, as a source_document with
            // that ID doesn't exist. However, it's not worse than the situation before, where we
            // returned an ID struct with the digest. This loader is just not aligned with the
            // design.
            id: digests.sha512.encode_hex(),
            document_id: Some("CWE".to_string()),
            warnings: vec![],
        })
    }
}

fn normalize(vec: Vec<String>) -> Option<Vec<String>> {
    if vec.is_empty() {
        None
    } else {
        Some(canonicalize(vec))
    }
}

fn canonicalize(vec: Vec<String>) -> Vec<String> {
    vec.iter().map(|e| format!("CWE-{e}")).collect()
}

fn gather_content(node: &Node) -> String {
    let mut dest = String::new();

    let children = node.children();

    for child in children {
        gather_content_inner(&child, &mut dest);
    }

    dest.trim().to_string()
}

fn gather_content_inner(node: &Node, dest: &mut String) {
    if node.is_element() {
        dest.push_str(&format!("<{}>", node.tag_name().name()));
        for child in node.children() {
            gather_content_inner(&child, dest);
        }
        dest.push_str(&format!("</{}>", node.tag_name().name()));
    } else if node.is_text()
        && let Some(text) = node.text()
    {
        dest.push_str(text);
    }
}

#[cfg(test)]
mod test {
    use crate::service::weakness::CweCatalogLoader;
    use roxmltree::Document;
    use std::io::Read;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::hashing::HashingRead;
    use trustify_entity::labels::Labels;
    use trustify_test_context::TrustifyContext;
    use trustify_test_context::document_read;
    use zip::ZipArchive;

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn test(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let loader = CweCatalogLoader::new();

        let zip = document_read("cwec_latest.xml.zip")?;

        let mut archive = ZipArchive::new(zip)?;

        let entry = archive.by_index(0)?;

        let mut hashing = HashingRead::new(entry);
        let mut xml = String::new();
        hashing.read_to_string(&mut xml)?;
        let digests = hashing.finish()?;
        let doc = Document::parse(&xml)?;

        // should work twice without error/conflict.

        ctx.db
            .transaction(async |tx| loader.load(Labels::default(), &doc, &digests, tx).await)
            .await?;

        ctx.db
            .transaction(async |tx| loader.load(Labels::default(), &doc, &digests, tx).await)
            .await?;

        Ok(())
    }
}
