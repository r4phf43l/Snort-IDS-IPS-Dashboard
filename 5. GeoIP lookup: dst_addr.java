rule "GeoIP lookup: dst_addr"
when
  has_field("dst_addr")
then
  let geo = lookup("geoip", to_string($message.dst_addr));
  set_field("dst_ip_geo_location", geo["coordinates"]);
  set_field("dst_ip_geo_country", geo["country"].iso_code);
  set_field("dst_ip_geo_city", geo["city"].names.en);
  set_field("dst_ip_geo_geoname_id", geo["geoname_id"]);
end
