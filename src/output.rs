pub fn sanitize_graphite(s: &String) -> String {
    s.replace("-", "_").replace(".", "__").replace("/", "_")
}
