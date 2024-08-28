rule "Extract e2Guardian alert fields"
when
    has_field("message") AND
    contains(to_string($message.message), "e2guardian")
then
    let m = regex("^(.+?)\\[(\\d+)\\]:\\s(.+?):\\s(.+?)$", to_string($message.message));
    set_field("application_name", m["0"]);
    set_field("pid", m["1"]);
    set_field("hw", m["2"]);
    set_field("alert", m["3"]);
end
