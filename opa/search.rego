package search

default decision := {
  "allow": false,
  "redactSnippet": false,
  "redactPath": false,
}

decision := {
  "allow": allow,
  "redactSnippet": redact_snippet,
  "redactPath": redact_path,
} {
  allow := allow_search
  redact_snippet := should_redact_snippet
  redact_path := should_redact_path
}

allow_search {
  input.action == "start_search"
  not denied_path(input.request.root)
}

allow_search {
  input.action == "read_search_result"
  not denied_path(input.match.path)
}

should_redact_snippet {
  input.action == "read_search_result"
  looks_sensitive(input.match.text)
}

should_redact_snippet {
  input.action == "read_search_result"
  denied_path(input.match.path)
}

should_redact_path {
  input.action == "read_search_result"
  denied_path(input.match.path)
}

denied_path(path) {
  startswith(path, ".")
}

denied_path(path) {
  contains(path, "/.git/")
}

denied_path(path) {
  contains(path, "/node_modules/")
}

denied_path(path) {
  endswith(path, ".env")
}

denied_path(path) {
  endswith(path, ".env.local")
}

denied_path(path) {
  endswith(path, ".pem")
}

denied_path(path) {
  endswith(path, ".key")
}

denied_path(path) {
  endswith(path, ".p12")
}

looks_sensitive(text) {
  regex.match("(?i)(password|passwd|secret|token|api[_-]?key|authorization)", text)
}

looks_sensitive(text) {
  regex.match("AKIA[0-9A-Z]{16}", text)
}

looks_sensitive(text) {
  regex.match("(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", text)
}

looks_sensitive(text) {
  looks_like_pii(text)
}

looks_sensitive(text) {
  looks_like_phi(text)
}

looks_like_pii(text) {
  regex.match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", text)
}

looks_like_pii(text) {
  regex.match("\\b\\d{3}-\\d{2}-\\d{4}\\b", text)
}

looks_like_pii(text) {
  regex.match("\\b(?:\\+?1[-. ]?)?(?:\\(\\d{3}\\)|\\d{3})[-. ]?\\d{3}[-. ]?\\d{4}\\b", text)
}

looks_like_pii(text) {
  regex.match("\\b\\d{13,19}\\b", text)
}

looks_like_phi(text) {
  regex.match("(?i)\\b(patient|diagnosis|treatment|medication|prescription|allerg(y|ies)|mrn|chart\\s*number|medical\\s*record\\s*number)\\b", text)
}

looks_like_phi(text) {
  regex.match("(?i)\\b(icd-?10|cpt|npi|hipaa|ehr|emr)\\b", text)
}
