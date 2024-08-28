rule "GeoIP lookup: src_addr"
when
  has_field("src_addr")
then
  let geo = lookup("geoip", to_string($message.src_addr));
  set_field("src_ip_geo_location", geo["coordinates"]);
  set_field("src_ip_geo_country", geo["country"].iso_code);
  set_field("src_ip_geo_city", geo["city"].names.en);
  set_field("src_ip_geo_geoname_id", geo["geoname_id"]);
end
