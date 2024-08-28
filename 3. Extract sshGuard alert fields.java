rule "Extract sshGuard alert fields"
when
    has_field("message") AND
    contains(to_string($message.message), "sshguard")
then
    let m = regex("^(.+?)\\[(\\d+)\\]:\\s(.+?)$", to_string($message.message));
    set_field("application_name", m["0"]);
    set_field("pid", m["1"]);
    set_field("alert", m["2"]);
end
