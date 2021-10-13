pub fn sanitize_graphite(s: &str) -> String {
    s.replace("-", "_").replace(".", "__").replace("/", "_")
}
