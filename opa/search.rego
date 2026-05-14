package search
import rego.v1

default decision.allow := false
default decision.redactSnippet := false
default decision.redactPath := false
default decision.passwordKeywordDetected := false
default decision.passwdKeywordDetected := false
default decision.apiKeyKeywordDetected := false
default decision.authorizationKeywordDetected := false
default decision.secretKeywordDetected := false
default decision.awsAccessKeyDetected := false
default decision.privateKeyMaterialDetected := false
default decision.emailAddressDetected := false
default decision.ssnDetected := false
default decision.phoneNumberDetected := false
default decision.paymentCardDetected := false
default decision.healthcareTerminologyDetected := false
default decision.healthcareAcronymDetected := false
default decision.dotfilePathDetected := false
default decision.gitMetadataPathDetected := false
default decision.nodeModulesPathDetected := false
default decision.environmentFilePathDetected := false
default decision.privateKeyFileDetected := false

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

decision.passwordKeywordDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)password", input.match.text)
}

decision.passwdKeywordDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)passwd", input.match.text)
}

decision.apiKeyKeywordDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)api[_-]?key", input.match.text)
}

decision.authorizationKeywordDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)authorization", input.match.text)
}

decision.secretKeywordDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)secret", input.match.text)
}

decision.awsAccessKeyDetected := true if {
  input.action == "read_search_result"
  regex.match("AKIA[0-9A-Z]{16}", input.match.text)
}

decision.privateKeyMaterialDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", input.match.text)
}

decision.emailAddressDetected := true if {
  input.action == "read_search_result"
  regex.match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", input.match.text)
}

decision.ssnDetected := true if {
  input.action == "read_search_result"
  regex.match("\\b\\d{3}-\\d{2}-\\d{4}\\b", input.match.text)
}

decision.phoneNumberDetected := true if {
  input.action == "read_search_result"
  regex.match("\\b(?:\\+?1[-. ]?)?(?:\\(\\d{3}\\)|\\d{3})[-. ]?\\d{3}[-. ]?\\d{4}\\b", input.match.text)
}

decision.paymentCardDetected := true if {
  input.action == "read_search_result"
  regex.match("\\b\\d{13,19}\\b", input.match.text)
}

decision.healthcareTerminologyDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)\\b(patient|diagnosis|treatment|medication|prescription|allerg(y|ies)|mrn|chart\\s*number|medical\\s*record\\s*number)\\b", input.match.text)
}

decision.healthcareAcronymDetected := true if {
  input.action == "read_search_result"
  regex.match("(?i)\\b(icd-?10|cpt|npi|hipaa|ehr|emr)\\b", input.match.text)
}

decision.dotfilePathDetected := true if {
  input.action == "read_search_result"
  startswith(input.match.path, ".")
}

decision.gitMetadataPathDetected := true if {
  input.action == "read_search_result"
  contains(input.match.path, "/.git/")
}

decision.nodeModulesPathDetected := true if {
  input.action == "read_search_result"
  contains(input.match.path, "/node_modules/")
}

decision.environmentFilePathDetected := true if {
  input.action == "read_search_result"
  endswith(input.match.path, ".env")
}

decision.environmentFilePathDetected := true if {
  input.action == "read_search_result"
  endswith(input.match.path, ".env.local")
}

decision.privateKeyFileDetected := true if {
  input.action == "read_search_result"
  endswith(input.match.path, ".pem")
}

decision.privateKeyFileDetected := true if {
  input.action == "read_search_result"
  endswith(input.match.path, ".key")
}

decision.privateKeyFileDetected := true if {
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
