# Snort-IDS-IPS-Dashboard
A Snort IDS/IPS dashboard build on Elastisearch, using data parsed from Graylog. Based on template 11191.

After creating the Input, it is necessary to create the pipelines in the following order:

# Stage 1

## Extract e2Guardian alert fields (optional)
## Extract Snort alert fields (mandatory)
## Extract sshGuard alert fields (mandatory)
## SSH: Extract attempted login remote IP (mandatory)

# Stage 2

## GeoIP lookup: dst_addr
## GeoIP lookup: dst_ip
