/// escape values for putting them into a `q` parameter
pub fn escape_q(q: impl AsRef<str>) -> String {
    let q = q.as_ref();

    q.replace('\\', "\\\\")
        .replace('&', "\\&")
        .replace('=', "\\=")
}
