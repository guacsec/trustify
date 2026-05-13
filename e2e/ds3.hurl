# Upload the dataset
POST http://localhost:8080/api/v3/dataset
file,etc/datasets/ds3.zip;

HTTP 201

[Asserts]
jsonpath "$.files.['spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2'].id" exists
jsonpath "$.files.['spdx/ubi8-8.8-1067.json.bz2'].id" exists
jsonpath "$.files.['csaf/2023/cve-2023-0044.json'].id" exists

[Captures]
quarkus_sbom_id: jsonpath "$.files.['spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2'].id"
ubi8_sbom_id: jsonpath "$.files.['spdx/ubi8-8.8-1067.json.bz2'].id"
advisory_id: jsonpath "$.files.['csaf/2023/cve-2023-0044.json'].id"


# Check vulnerabilities for UBI 8 SBOM
GET http://localhost:8080/api/v3/sbom/{{ubi8_sbom_id}}/advisory

HTTP 200

[Asserts]
jsonpath "$[?(@.document_id == 'CVE-2024-28834')].status[?(@.context.cpe == 'cpe:/a:redhat:enterprise_linux:8:*:appstream:*')]" count == 1

# Check purl vulnerability date
GET http://localhost:8080/api/v3/purl/3a5c8e1e-17c4-5715-b74c-f8b61c4d7d8c
HTTP 200

[Asserts]
jsonpath "$.advisories[*].status[*].vulnerability.published" not isEmpty


# Check vulnerability title
GET http://localhost:8080/api/v3/vulnerability/CVE-2023-21971
HTTP 200

[Asserts]
jsonpath "$.title" not isEmpty

## Test delete and re-upload advisory
DELETE http://localhost:8080/api/v3/advisory/{{advisory_id}}

HTTP 200

POST http://localhost:8080/api/v3/advisory
file,etc/datasets/ds3/csaf/2023/cve-2023-0044.json;

HTTP 201
