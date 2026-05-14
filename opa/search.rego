package search
import rego.v1

default decision := {
  "allow": false,
  "redactSnippet": false,
  "redactPath": false,
}

decision := {
  "allow": true,
  "redactSnippet": false,
  "redactPath": false,
} if {
  input.action == "start_search"
  not denied_path(input.request.root)
}

decision := {
  "allow": true,
  "redactSnippet": looks_sensitive(input.match.text) or denied_path(input.match.path),
  "redactPath": denied_path(input.match.path),
} if {
  input.action == "read_search_result"
  not denied_path(input.match.path)
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
