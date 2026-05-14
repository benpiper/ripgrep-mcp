package search
import rego.v1

default decision.allow := false
default decision.redactSnippet := false
default decision.redactPath := false

decision.allow := true if {
  input.action == "start_search"
  not denied_path(input.request.root)
}

decision.allow := true if {
  input.action == "read_search_result"
  not denied_path(input.match.path)
}

decision.redactSnippet := true if {
  input.action == "read_search_result"
  looks_sensitive(input.match.text)
}

decision.redactSnippet := true if {
  input.action == "read_search_result"
  denied_path(input.match.path)
}

decision.redactPath := true if {
  input.action == "read_search_result"
  denied_path(input.match.path)
}

decision.reasonCodes contains "password_keyword" if {
  input.action == "read_search_result"
  regex.match("(?i)password", input.match.text)
}

decision.reasonCodes contains "passwd_keyword" if {
  input.action == "read_search_result"
  regex.match("(?i)passwd", input.match.text)
}

decision.reasonCodes contains "api_key_keyword" if {
  input.action == "read_search_result"
  regex.match("(?i)api[_-]?key", input.match.text)
}

decision.reasonCodes contains "authorization_keyword" if {
  input.action == "read_search_result"
  regex.match("(?i)authorization", input.match.text)
}

decision.reasonCodes contains "secret_keyword" if {
  input.action == "read_search_result"
  regex.match("(?i)secret", input.match.text)
}

decision.reasonCodes contains "aws_access_key" if {
  input.action == "read_search_result"
  regex.match("AKIA[0-9A-Z]{16}", input.match.text)
}

decision.reasonCodes contains "private_key_material" if {
  input.action == "read_search_result"
  regex.match("(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", input.match.text)
}

decision.reasonCodes contains "email_address" if {
  input.action == "read_search_result"
  regex.match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", input.match.text)
}

decision.reasonCodes contains "ssn" if {
  input.action == "read_search_result"
  regex.match("\\b\\d{3}-\\d{2}-\\d{4}\\b", input.match.text)
}

decision.reasonCodes contains "phone_number" if {
  input.action == "read_search_result"
  regex.match("\\b(?:\\+?1[-. ]?)?(?:\\(\\d{3}\\)|\\d{3})[-. ]?\\d{3}[-. ]?\\d{4}\\b", input.match.text)
}

decision.reasonCodes contains "payment_card_number" if {
  input.action == "read_search_result"
  regex.match("\\b\\d{13,19}\\b", input.match.text)
}

decision.reasonCodes contains "healthcare_terminology" if {
  input.action == "read_search_result"
  regex.match("(?i)\\b(patient|diagnosis|treatment|medication|prescription|allerg(y|ies)|mrn|chart\\s*number|medical\\s*record\\s*number)\\b", input.match.text)
}

decision.reasonCodes contains "healthcare_acronym" if {
  input.action == "read_search_result"
  regex.match("(?i)\\b(icd-?10|cpt|npi|hipaa|ehr|emr)\\b", input.match.text)
}

decision.reasonCodes contains "dotfile_path" if {
  input.action == "read_search_result"
  startswith(input.match.path, ".")
}

decision.reasonCodes contains "git_metadata_path" if {
  input.action == "read_search_result"
  contains(input.match.path, "/.git/")
}

decision.reasonCodes contains "node_modules_path" if {
  input.action == "read_search_result"
  contains(input.match.path, "/node_modules/")
}

decision.reasonCodes contains "environment_file_path" if {
  input.action == "read_search_result"
  endswith(input.match.path, ".env")
}

decision.reasonCodes contains "environment_file_path" if {
  input.action == "read_search_result"
  endswith(input.match.path, ".env.local")
}

decision.reasonCodes contains "private_key_file_path" if {
  input.action == "read_search_result"
  endswith(input.match.path, ".pem")
}

decision.reasonCodes contains "private_key_file_path" if {
  input.action == "read_search_result"
  endswith(input.match.path, ".key")
}

decision.reasonCodes contains "private_key_file_path" if {
  input.action == "read_search_result"
  endswith(input.match.path, ".p12")
}

denied_path(path) if {
  startswith(path, ".")
}

denied_path(path) if {
  contains(path, "/.git/")
}

denied_path(path) if {
  contains(path, "/node_modules/")
}

denied_path(path) if {
  endswith(path, ".env")
}

denied_path(path) if {
  endswith(path, ".env.local")
}

denied_path(path) if {
  endswith(path, ".pem")
}

denied_path(path) if {
  endswith(path, ".key")
}

denied_path(path) if {
  endswith(path, ".p12")
}

looks_sensitive(text) if {
  regex.match("(?i)(password|passwd|secret|token|api[_-]?key|authorization)", text)
}

looks_sensitive(text) if {
  regex.match("AKIA[0-9A-Z]{16}", text)
}

looks_sensitive(text) if {
  regex.match("(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", text)
}

looks_sensitive(text) if {
  looks_like_pii(text)
}

looks_sensitive(text) if {
  looks_like_phi(text)
}

looks_like_pii(text) if {
  regex.match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", text)
}

looks_like_pii(text) if {
  regex.match("\\b\\d{3}-\\d{2}-\\d{4}\\b", text)
}

looks_like_pii(text) if {
  regex.match("\\b(?:\\+?1[-. ]?)?(?:\\(\\d{3}\\)|\\d{3})[-. ]?\\d{3}[-. ]?\\d{4}\\b", text)
}

looks_like_pii(text) if {
  regex.match("\\b\\d{13,19}\\b", text)
}

looks_like_phi(text) if {
  regex.match("(?i)\\b(patient|diagnosis|treatment|medication|prescription|allerg(y|ies)|mrn|chart\\s*number|medical\\s*record\\s*number)\\b", text)
}

looks_like_phi(text) if {
  regex.match("(?i)\\b(icd-?10|cpt|npi|hipaa|ehr|emr)\\b", text)
}
