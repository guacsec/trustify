No OSV/GHSA records: bind (ISC BIND) ships as an OS RPM, not a language-ecosystem
package. The OSV/GitHub Advisory DB does not carry pkg:rpm/redhat/bind-libs
coordinates, so there is no OSV file for these CVEs. Correlation for bind-libs is
CSAF/VEX-only. (This is itself relevant: only the Red Hat product_status path applies.)
