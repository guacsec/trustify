Database layout for storing SBOM information.

When storing an SBOM, we extract parts of it into the database, and also store the full document should we need it in
the future.

We do extract the following components out of the SBOM:

* Basic document metadata
* Packages
* Files
* Relationships between those nodes

We also detect PURLs and CPEs, and create database entries for those as well if they don't exist yet.

An SBOM contains a list of nodes, which are connected by relationships (like A depends on B). For some SBOM formats
(e.g. SPDX), this may include references to the document itself (A describes SBOM), or to external documents
(SBOM-A amends SBOM-B) and nodes in external documents (A depends on SBOM-B/C).

A node can be the SBOM itself, a package (aka component), a file, or another part of the SBOM.

To represent this graph of SBOM, packages, files and relationships, the model of SPDX is being used, as it also covers
the features of CycloneDX. In the database, this is being represented by the following structure:

```mermaid
erDiagram
    sbom {
        uuid sbom_id PK, FK "unique ID of the SBOM"
        string node_id "ID of the SBOM document element in the scope of this SBOM"

        string document_id "ID from the content of the document"
        string sha256 "SHA256 digest of the document content"
    }

    sbom_package {
        uuid sbom_id PK, FK "unique ID of the SBOM this package belongs"
        string node_id PK, FK "ID of the SBOM package element in the scope of this SBOM"
        string version "The version of the package"
    }

    sbom_file {
        uuid sbom_id PK, FK "unique ID of the SBOM this file belongs"
        string node_id PK, FK "ID of the SBOM file element in the scope of this SBOM"
    }

    sbom_node {
        uuid sbom_id PK "unique ID of the SBOM this node belongs to"
        string node_id PK "ID of the SBOM element in the scope of this SBOM"
        
        string name "The name of the node"
    }

    package_relates_to_package {
        int sbom_id
        string left_node_id
        enum~relationship~ type
        string right_node_id
    }

    sbom 1 to 0+ sbom_package: contains

    base_purl {
        uuid id
        string type
        string name
        option~string~ namespace
    }
    versioned_purl {
        string version
    }
    qualified_purl {
        jsonb qualifiers
    }

    qualified_purl 0+ to 1 versioned_purl: refines
    versioned_purl 0+ to 1 base_purl: refines
    cpe

    sbom_node 1 optionally to 0+ qualified_purl: names
    sbom_node 1 optionally to 0+ cpe: names

    sbom_node 1 to zero or one sbom_file: inherits
    sbom_node 1 to zero or one sbom_package: inherits
    sbom_node 1 to zero or one sbom: inherits
    package_relates_to_package 1 to zero or one sbom_node: left
    package_relates_to_package 1 to zero or one sbom_node: right
```

The `sbom_node` table contains all possible targets for references. This can be either an SBOM, a package of an SBOM, or
a file of the SBOM. So a node consists of the base node information in the `sbom_node` table, as well as exactly one
corresponding entry in either table of `sbom_package`, `sbom_file`, or `sbom`.

Creating a matching entry in one of those tables will make that node a type of this. e.g. adding a corresponding entry
in the `sbom_package` table makes this an SBOM package node.

The relationship table links the nodes together, creating the graph inside that SBOM.

The SBOM ID is an artificially generated unique ID. The node IDs are taken from the content of the SBOM and are only
considered unique in the scope of the SBOM. The import process will enforce the uniqueness of the Node IDs.

The trio of `QualifiedPurl`, `VersionedPurl`, and `BasePurl` describe what used to be known as "package", but which did
not fully reflect the SBOMs model, as SBOM packages are an entity of their own, but may have zero or more PURLs or
CPEs (or other identifiers).
