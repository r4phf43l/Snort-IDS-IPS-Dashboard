rule "SSH: Extract attempted login remote IP"
when
 has_field("message")
then
 let r = regex(".+from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) port.+", to_string($message.message));
 set_field("src_addr", r["0"]);
end
