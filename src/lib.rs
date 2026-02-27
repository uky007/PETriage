pub mod rich_db;
pub mod analysis;
pub mod output;
#[cfg(feature = "gui")]
pub mod gui;

/// Parse a PE with lenient fallback: if strict parsing fails (e.g. malformed
/// certificate table), retry with `parse_attribute_certificates: false`.
/// Returns `(PE, Option<warning_message>)` on success.
pub fn parse_pe_lenient<'a>(data: &'a [u8], label: &str) -> Result<(goblin::pe::PE<'a>, Option<String>), String> {
    match goblin::pe::PE::parse(data) {
        Ok(pe) => Ok((pe, None)),
        Err(first_err) => {
            let opts = goblin::pe::options::ParseOptions {
                resolve_rva: true,
                parse_attribute_certificates: false,
            };
            match goblin::pe::PE::parse_with_opts(data, &opts) {
                Ok(pe) => {
                    let warning = format!(
                        "{} had a parse issue ({}); continuing with certificate table parsing disabled",
                        label, first_err
                    );
                    Ok((pe, Some(warning)))
                }
                Err(e) => Err(format!("Failed to parse PE '{}': {}", label, e)),
            }
        }
    }
}
