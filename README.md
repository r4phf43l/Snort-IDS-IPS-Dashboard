# Snort-IDS-IPS-Dashboard
A Snort IDS/IPS dashboard build on Elastisearch, using data parsed from Graylog. Based on template 11191.

# On Graylog:

Create the Input;

Import the 0. Extractors.json;

Then, It is necessary to create the pipelines in the following order:

## Stage 1

1. Extract e2Guardian alert fields (optional)
2. Extract Snort alert fields (mandatory)
3. Extract sshGuard alert fields (mandatory)
4. SSH: Extract attempted login remote IP (mandatory)

## Stage 2

5. GeoIP lookup: dst_addr
6. GeoIP lookup: src_addr

# On Grafana:

Configure the ElasticSearch;

Import the template.
