# Upload a CVE document listed in the KEV catalog
POST http://localhost:8080/api/v3/advisory
file,etc/test-data/cve/CVE-2025-6965.json;

HTTP 201


# Upload the CISA KEV catalog
POST http://localhost:8080/api/v3/advisory?format=cisakev
file,etc/test-data/kev/known_exploited_vulnerabilities.json;

HTTP 201


# Vulnerability details expose the catalog entry
GET http://localhost:8080/api/v3/vulnerability/CVE-2025-6965

HTTP 200

[Asserts]
jsonpath "$.known_exploited" count == 1
jsonpath "$.known_exploited[0].source" == "cisa"
jsonpath "$.known_exploited[0].date_added" == "2025-07-17"
jsonpath "$.known_exploited[0].due_date" == "2025-08-07"


# A vulnerability not listed in the catalog has no entries
POST http://localhost:8080/api/v3/advisory
file,etc/test-data/cve/CVE-2021-32714.json;

HTTP 201

GET http://localhost:8080/api/v3/vulnerability/CVE-2021-32714

HTTP 200

[Asserts]
jsonpath "$.known_exploited" count == 0
