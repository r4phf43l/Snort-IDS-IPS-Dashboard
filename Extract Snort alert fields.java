rule "Extract Snort alert fields"
when
    has_field("message") AND
    contains(to_string($message.message), "snort")
then
    let m = regex("^(.+?)\\[(\\d+)\\]:\\s\\[(\\d+):(\\d+):(\\d+)]\\s(.+?)\\s\\[Classification:\\s(.+?)]\\s\\[Priority:\\s(\\d+)]\\s\\{(.+?)}\\s(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})\\:(\\d{1,5})\\s\\->\\s(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})\\:(\\d{1,5})", to_string($message.message));
    set_field("application_name", m["0"]);
    set_field("pid", m["1"]);
    set_field("generator_id", m["2"]);
    set_field("signature_id", m["3"]);
    set_field("signature_revision_id", m["4"]);
    set_field("description", m["5"]);
    set_field("classification", m["6"]);
    set_field("priority", m["7"]);
    set_field("protocol", m["8"]);
    set_field("src_addr", m["9"]);
    set_field("src_port", m["10"]);
    set_field("dst_addr", m["11"]);
    set_field("dst_port", m["12"]);
end
